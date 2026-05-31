"""Distributed worker for recon, malware, sandbox, and AI tasks."""

import asyncio
import base64
import os
import uuid

from backend.graph_stream import GraphStream
from services.ai.analyst import AIAnalyst
from services.graph.graph_engine import GraphService
from services.malware.ai_malware_analyst import AIMalwareAnalyst
from services.malware.sample_uploader import SampleUploader
from services.malware.static_analyzer import StaticAnalyzer
from services.malware.telemetry_collector import TelemetryCollector
from services.queue import QueueManager
from services.recon.service import ReconService
from services.reports.report_service import ReportService
from services.sandbox.controller import SandboxController


class DistributedWorker:
    def __init__(self, worker_id=None, capabilities=None):
        self.worker_id = worker_id or os.getenv("ARCHAI_WORKER_ID", f"worker-{uuid.uuid4().hex[:8]}")
        self.capabilities = capabilities or os.getenv("ARCHAI_WORKER_CAPABILITIES", "recon,malware,sandbox,ai").split(",")
        self.queue_manager = QueueManager()
        self.recon_service = ReconService()
        self.report_service = ReportService()
        self.graph_service = GraphService()
        self.sample_uploader = SampleUploader()
        self.static_analyzer = StaticAnalyzer()
        self.sandbox_controller = SandboxController()
        self.telemetry_collector = TelemetryCollector()
        self.malware_analyst = AIMalwareAnalyst()
        self.ai_analyst = AIAnalyst()
        self.graph_stream = GraphStream(self.queue_manager)

    async def publish_status(self, job_id, status, **metadata):
        self.queue_manager.persist_job_status(job_id, status, **metadata)
        event = {"type": "job_status", "job_id": job_id, "status": status, **metadata}
        await self.queue_manager.publish_async("telemetry", event)

    async def publish_telemetry(self, event_type, job_id, **payload):
        await self.queue_manager.publish_async(
            "telemetry",
            {"type": "telemetry", "event_type": event_type, "job_id": job_id, **payload},
        )

    async def heartbeat_loop(self):
        while True:
            self.queue_manager.worker_heartbeat(
                self.worker_id,
                {"capabilities": self.capabilities, "status": "online", "worker_type": "distributed"},
            )
            await asyncio.sleep(15)

    async def process_recon(self, payload):
        job_id = payload["job_id"]
        target = payload["target"]
        await self.publish_status(job_id, "running", queue="recon_queue", stage="recon", target=target)
        await self.publish_telemetry("scan_started", job_id, target=target)

        try:
            result = await self.recon_service.scan_async(target)
            report_file = self.report_service.generate_json_report(target, result)

            await self.graph_stream.publish_node("attack", target, target, {"kind": "host", "target": target})
            open_ports = result.get("open_ports") or result.get("masscan_ports") or []
            for port in open_ports:
                await self.publish_telemetry("port_discovered", job_id, target=target, port=port)
                await self.graph_stream.publish_node("attack", f"{target}:{port}", f"port:{port}", {"target": target, "port": port, "kind": "port"})
                await self.graph_stream.publish_edge("attack", f"edge:{target}:{port}", target, f"{target}:{port}", "listens_on")

            for url in result.get("katana_urls", []):
                await self.publish_telemetry("url_discovered", job_id, target=target, url=url)
                await self.graph_stream.publish_node("attack", f"url:{url}", url, {"target": target, "kind": "url"})
                await self.graph_stream.publish_edge("attack", f"edge:{target}:{url}", target, f"url:{url}", "hosts")

            attack_paths = self.graph_service.build_attack_graph(result)
            for path_index, path in enumerate(attack_paths[:5]):
                await self.publish_telemetry("attack_path_generated", job_id, target=target, path=path)
                await self.graph_stream.publish_node("attack", f"path:{job_id}:{path_index}", path, {"kind": "path"})
                await self.graph_stream.publish_edge("attack", f"edge:{target}:{path_index}", target, f"path:{job_id}:{path_index}", "leads_to")

            await self.publish_status(
                job_id,
                "completed",
                queue="recon_queue",
                stage="recon",
                report_file=report_file,
                result=result,
            )
            await self.publish_telemetry("scan_completed", job_id, target=target, report_file=report_file)
        except Exception as exc:
            await self.publish_status(job_id, "failed", queue="recon_queue", error=str(exc))
            await self.publish_telemetry("scan_failed", job_id, target=target, error=str(exc))

    async def process_malware(self, payload):
        job_id = payload["job_id"]
        await self.publish_status(job_id, "running", queue="malware_queue", stage="static_analysis")

        try:
            metadata = payload.get("metadata")
            content_bytes = payload.get("content_bytes")
            if content_bytes is None and payload.get("content_base64"):
                content_bytes = base64.b64decode(payload["content_base64"])
            if metadata is None:
                metadata = self.sample_uploader.ingest(payload["filename"], content_bytes)

            static_analysis = self.static_analyzer.analyze(metadata)
            sandbox_job = self.sandbox_controller.create_job(metadata, payload.get("network_mode", "isolated"))
            telemetry = self.telemetry_collector.collect(sandbox_job)
            ai_summary = self.malware_analyst.summarize(metadata, static_analysis, telemetry)

            await self.graph_stream.publish_node("malware", metadata["sample_id"], metadata["filename"], {"kind": "sample", "sha256": metadata["sha256"]})
            await self.graph_stream.publish_edge("malware", f"edge:{metadata['sample_id']}:{sandbox_job['job_id']}", metadata["sample_id"], sandbox_job["job_id"], "queued_for_sandbox")

            await self.publish_status(
                job_id,
                "completed",
                queue="malware_queue",
                stage="static_analysis",
                metadata=metadata,
                static_analysis=static_analysis,
                sandbox_job=sandbox_job,
                telemetry=telemetry,
                ai_summary=ai_summary,
            )
            await self.publish_telemetry("malware_analysis_completed", job_id, filename=metadata["filename"], sample_id=metadata["sample_id"])
        except Exception as exc:
            await self.publish_status(job_id, "failed", queue="malware_queue", error=str(exc))
            await self.publish_telemetry("malware_analysis_failed", job_id, error=str(exc))

    async def process_sandbox(self, payload):
        job_id = payload["job_id"]
        sample_id = payload.get("sample_id")
        filename = payload.get("filename", sample_id)
        await self.publish_status(job_id, "running", queue="sandbox_queue", stage="sandbox", sample_id=sample_id)

        try:
            sandbox_job = self.sandbox_controller.create_job(
                {"sample_id": sample_id, "filename": filename},
                payload.get("network_mode", "isolated"),
            )
            plan = self.sandbox_controller.plan_job(sandbox_job)
            await self.publish_telemetry("sandbox_plan_ready", job_id, sample_id=sample_id, plan=plan)

            if plan.get("status") != "ready":
                await self.publish_status(job_id, "queued", queue="sandbox_queue", stage="sandbox", sandbox_plan=plan)
                await self.publish_telemetry("sandbox_waiting", job_id, sample_id=sample_id, reason=plan.get("reason"))
                return

            restore = self.sandbox_controller.restore_snapshot(sandbox_job)
            await self.publish_telemetry("sandbox_restore", job_id, status=restore.get("status"), tool=restore.get("tool"))

            transfer = self.sandbox_controller.transfer_sample(sandbox_job, payload.get("sample_path"))
            await self.publish_telemetry("sample_transferred", job_id, status=transfer.get("status"), target=transfer.get("target_path"))

            execute = self.sandbox_controller.execute_sample(sandbox_job, payload.get("sample_path"))
            await self.publish_telemetry("sample_executed", job_id, status=execute.get("status"), tool=execute.get("tool"))

            telemetry = self.sandbox_controller.collect_telemetry(sandbox_job)
            pcap = self.sandbox_controller.save_pcap(sandbox_job)
            destroy = self.sandbox_controller.destroy_vm_session(sandbox_job)

            await self.publish_status(
                job_id,
                "completed",
                queue="sandbox_queue",
                stage="sandbox",
                sandbox_job=sandbox_job,
                sandbox_plan=plan,
                telemetry=telemetry,
                pcap=pcap,
                destroy=destroy,
            )
            await self.publish_telemetry("sandbox_completed", job_id, sample_id=sample_id, pcap_path=pcap.get("pcap_path"))
            await self.graph_stream.publish_node("malware", sandbox_job["job_id"], f"sandbox:{sample_id}", {"kind": "sandbox", "sample_id": sample_id})
            await self.graph_stream.publish_edge("malware", f"edge:{sample_id}:{sandbox_job['job_id']}", sample_id, sandbox_job["job_id"], "executed_in")
        except Exception as exc:
            await self.publish_status(job_id, "failed", queue="sandbox_queue", error=str(exc))
            await self.publish_telemetry("sandbox_failed", job_id, sample_id=sample_id, error=str(exc))

    async def process_ai(self, payload):
        job_id = payload["job_id"]
        await self.publish_status(job_id, "running", queue="ai_queue", stage="ai")

        try:
            summary = self.ai_analyst.summarize(payload.get("context") or {"prompt": payload.get("prompt", "")})
            await self.publish_status(job_id, "completed", queue="ai_queue", stage="ai", summary=summary)
            await self.publish_telemetry("ai_completed", job_id)
        except Exception as exc:
            await self.publish_status(job_id, "failed", queue="ai_queue", error=str(exc))
            await self.publish_telemetry("ai_failed", job_id, error=str(exc))

    async def consume(self, queue_name, handler):
        while True:
            task = self.queue_manager.claim_job(queue_name, self.worker_id)
            if task is None:
                await asyncio.sleep(1)
                continue
            asyncio.create_task(handler(task))

    async def register(self):
        self.queue_manager.register_worker(
            self.worker_id,
            capabilities=self.capabilities,
            metadata={"worker_type": "distributed", "status": "online"},
        )
        await self.publish_telemetry("worker_registered", self.worker_id, capabilities=self.capabilities)

    async def run(self):
        await self.register()
        tasks = [asyncio.create_task(self.heartbeat_loop())]
        if "recon" in self.capabilities:
            tasks.append(asyncio.create_task(self.consume("recon_queue", self.process_recon)))
        if "malware" in self.capabilities:
            tasks.append(asyncio.create_task(self.consume("malware_queue", self.process_malware)))
        if "sandbox" in self.capabilities:
            tasks.append(asyncio.create_task(self.consume("sandbox_queue", self.process_sandbox)))
        if "ai" in self.capabilities:
            tasks.append(asyncio.create_task(self.consume("ai_queue", self.process_ai)))

        await asyncio.gather(*tasks)


async def main():
    worker = DistributedWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
