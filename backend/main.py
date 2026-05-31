"""FastAPI backend exposing modular ARCHAI X services."""

import asyncio
import base64
import uuid

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from backend.models import AIRequest, MalwareUploadRequest, SandboxRequest, ScanRequest
from backend.tasks import (
    dispatch_ai_summary,
    dispatch_malware_analysis,
    dispatch_sandbox_execution,
)
from backend.telemetry_router import TelemetryRouter
from backend.websocket_manager import WebSocketManager
from services.ai.analyst import AIAnalyst
from services.graph.graph_engine import GraphService
from services.malware.ai_malware_analyst import AIMalwareAnalyst
from services.malware.sample_uploader import SampleUploader
from services.sandbox.controller import SandboxController
from services.malware.static_analyzer import StaticAnalyzer
from services.malware.telemetry_collector import TelemetryCollector
from services.queue import QueueManager
from services.reports.report_service import ReportService

app = FastAPI(title="ARCHAI X API", version="0.1.0")

queue_manager = QueueManager()
report_service = ReportService()
graph_service = GraphService()
websocket_manager = WebSocketManager()
telemetry_router = TelemetryRouter(queue_manager, websocket_manager)

sample_uploader = SampleUploader()
static_analyzer = StaticAnalyzer()
sandbox_controller = SandboxController()
telemetry_collector = TelemetryCollector()
malware_analyst = AIMalwareAnalyst()
ai_analyst = AIAnalyst()

app.state.jobs = {}


@app.on_event("startup")
async def startup():
    await telemetry_router.start()


@app.get("/")
async def root():
    return {"service": "ARCHAI X", "status": "online", "mode": "modular"}


@app.get("/api/recon/health")
async def recon_health():
    return {
        "status": "ok",
        "backend": "fastapi",
        "workers": "queue-ready",
        "queue_backend": queue_manager._backend(),
    }


@app.post("/api/recon/scan")
async def start_recon_scan(scan_request: ScanRequest):
    job = queue_manager.enqueue_job(
        "recon_queue",
        {
            "job_id": uuid.uuid4().hex,
            "task_type": "recon",
            "target": scan_request.target,
            "scan_level": scan_request.scan_level,
            "status": "queued",
        },
    )
    app.state.jobs[job["job_id"]] = job
    await queue_manager.publish_async("telemetry", {"type": "job_status", **job})
    return {"job_id": job["job_id"], "status": "queued", "queue": "recon_queue"}


@app.get("/api/recon/jobs/{job_id}")
async def get_recon_job(job_id: str):
    job = queue_manager.get_job(job_id) or app.state.jobs.get(job_id)
    if not job:
        return {"job_id": job_id, "status": "missing"}
    return job


@app.get("/api/workers/status")
async def worker_status():
    return {"workers": queue_manager.list_workers(), "metrics": queue_manager.queue_metrics()}


@app.post("/api/malware/upload")
async def malware_upload(payload: MalwareUploadRequest):
    content_bytes = base64.b64decode(payload.content_base64)
    metadata = sample_uploader.ingest(payload.filename, content_bytes)
    static_report = static_analyzer.analyze(metadata)

    job = queue_manager.enqueue_job(
        "malware_queue",
        {
            "job_id": uuid.uuid4().hex,
            "task_type": "malware",
            "filename": payload.filename,
            "content_base64": payload.content_base64,
            "network_mode": "isolated",
            "status": "queued",
            "metadata": metadata,
            "static_analysis": static_report,
        },
    )
    app.state.jobs[job["job_id"]] = job
    await queue_manager.publish_async("telemetry", {"type": "job_status", **job})
    dispatch_malware_analysis.apply_async(
        kwargs={
            "job_id": job["job_id"],
            "metadata": metadata,
            "static_analysis": static_report,
            "filename": payload.filename,
            "network_mode": "isolated",
        },
        queue="malware_queue",
    )

    return {
        "metadata": metadata,
        "static_analysis": static_report,
        "job_id": job["job_id"],
        "status": "queued",
        "workflow": [
            "quarantine_storage",
            "metadata_extraction",
            "static_analysis",
            "sandbox_queue",
            "disposable_vm_execution",
            "telemetry_collection",
            "ai_analysis",
            "report_generation",
        ],
    }


@app.post("/api/malware/sandbox")
async def create_sandbox_job(payload: SandboxRequest):
    sandbox_job = sandbox_controller.create_job(
        {"sample_id": payload.sample_id, "filename": payload.sample_id},
        payload.network_mode,
    )
    job = queue_manager.enqueue_job(
        "sandbox_queue",
        {
            "job_id": sandbox_job["job_id"],
            "task_type": "sandbox",
            "sample_id": payload.sample_id,
            "filename": payload.sample_id,
            "network_mode": payload.network_mode,
            "status": "queued",
        },
    )
    app.state.jobs[job["job_id"]] = job
    await queue_manager.publish_async("telemetry", {"type": "job_status", **job})
    dispatch_sandbox_execution.apply_async(
        kwargs={
            "job_id": job["job_id"],
            "sample_id": payload.sample_id,
            "filename": payload.sample_id,
            "network_mode": payload.network_mode,
        },
        queue="sandbox_queue",
    )
    return {"job_id": job["job_id"], "status": "queued", "sandbox_job": sandbox_job}


@app.post("/api/ai/summarize")
async def summarize_ai(payload: AIRequest):
    job_id = uuid.uuid4().hex
    job = queue_manager.enqueue_job(
        "ai_queue",
        {
            "job_id": job_id,
            "task_type": "ai",
            "prompt": payload.prompt,
            "context": payload.context,
            "status": "queued",
        },
    )
    app.state.jobs[job_id] = job
    await queue_manager.publish_async("telemetry", {"type": "job_status", **job})

    task = dispatch_ai_summary.apply_async(
        kwargs={"job_id": job_id, "prompt": payload.prompt, "context": payload.context},
        queue="ai_queue",
    )

    try:
        summary = task.get(timeout=15)
        return {"summary": summary, "job_id": job_id, "status": "completed"}
    except Exception:
        return {"summary": "AI summarization is queued for remote worker execution.", "job_id": job_id, "status": "queued"}


@app.get("/api/graph/attack/{target}")
async def attack_graph(target: str):
    linked_job = next(
        (
            job
            for job in app.state.jobs.values()
            if job.get("target") == target and job.get("status") == "completed"
        ),
        None,
    )

    if not linked_job:
        return {"target": target, "status": "pending"}

    attack_graph = graph_service.build_attack_graph(linked_job["result"])
    visualization = graph_service.render_visualization(target, linked_job["result"].get("attack_paths", []))
    return {"target": target, "attack_graph": attack_graph, "visualization": visualization}


@app.get("/api/reports/{target}")
async def reports(target: str):
    for job in app.state.jobs.values():
        if job.get("target") == target and job.get("status") == "completed":
            return {"target": target, "report_file": job.get("report_file"), "result": job.get("result")}
    return {"target": target, "status": "pending"}


@app.websocket("/ws/telemetry")
async def telemetry_websocket(websocket: WebSocket):
    await websocket_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
