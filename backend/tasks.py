import os
from pathlib import Path

from backend.celery_app import celery_app
from backend.graph_stream import GraphStream
from services.ai.analyst import AIAnalyst
from services.malware.ai_malware_analyst import AIMalwareAnalyst
from services.queue import QueueManager
from services.reports.report_service import ReportService
from services.sandbox.controller import SandboxController

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
queue_manager = QueueManager(redis_url=redis_url)
report_service = ReportService()
ai_analyst = AIAnalyst()
malware_analyst = AIMalwareAnalyst()
sandbox_controller = SandboxController()
graph_stream = GraphStream(queue_manager)


def publish_telemetry(payload, channel="telemetry"):
    job_id = payload.get("job_id")
    if payload.get("type") == "job_status" and job_id:
        status_payload = dict(payload)
        status_payload.pop("job_id", None)
        queue_manager.persist_job_status(job_id, **status_payload)
    queue_manager.publish(channel, payload)
    if channel == "telemetry":
        queue_manager.publish("telemetry.recon", payload)
    return payload


def resolve_sample_path(sample_id):
    quarantine_dir = Path(os.getenv("QUARANTINE_DIR", "quarantine"))
    if not quarantine_dir.exists():
        return None

    matches = list(quarantine_dir.glob(f"{sample_id}_*"))
    return str(matches[0]) if matches else None


@celery_app.task(bind=True, name="backend.tasks.dispatch_malware_analysis")
def dispatch_malware_analysis(self, job_id, metadata, static_analysis, filename, network_mode="isolated"):
    publish_telemetry(
        {
            "type": "job_status",
            "job_id": job_id,
            "status": "running",
            "worker_id": self.request.hostname,
            "filename": filename,
            "network_mode": network_mode,
        }
    )

    try:
        summary = malware_analyst.summarize(metadata, static_analysis, {})
        report_file = report_service.generate_json_report(
            filename or metadata.get("filename", "malware"),
            {"static_analysis": static_analysis, "summary": summary, "metadata": metadata},
        )
        job = queue_manager.persist_job_status(
            job_id,
            status="completed",
            analysis_summary=summary,
            metadata=metadata,
            static_analysis=static_analysis,
            report_file=report_file,
        )

        publish_telemetry(
            {
                "type": "job_status",
                "job_id": job_id,
                "status": "completed",
                "worker_id": self.request.hostname,
                "filename": filename,
                "report_file": report_file,
            }
        )

        graph_stream.publish_node(
            "malware",
            metadata.get("sample_id", job_id),
            label=metadata.get("filename", filename),
            metadata={"analysis_mode": "malware"},
        )

        return job
    except Exception as exc:
        job = queue_manager.retry_failed_job("malware_queue", job_id, reason=str(exc))
        publish_telemetry(
            {
                "type": "job_status",
                "job_id": job_id,
                "status": job["status"],
                "worker_id": self.request.hostname,
                "filename": filename,
                "error": str(exc),
            }
        )
        raise


@celery_app.task(bind=True, name="backend.tasks.dispatch_sandbox_execution")
def dispatch_sandbox_execution(self, job_id, sample_id, filename, network_mode="isolated"):
    publish_telemetry(
        {
            "type": "job_status",
            "job_id": job_id,
            "status": "running",
            "worker_id": self.request.hostname,
            "sample_id": sample_id,
            "filename": filename,
            "network_mode": network_mode,
        }
    )

    try:
        sandbox_job = sandbox_controller.create_job(
            {"sample_id": sample_id, "filename": filename or sample_id},
            network_mode,
        )
        plan = sandbox_controller.plan_job(sandbox_job)
        if plan.get("status") != "ready":
            raise RuntimeError("Sandbox execution cannot start until a supported hypervisor is available.")

        sample_path = resolve_sample_path(sample_id)
        if sample_path is None:
            raise FileNotFoundError(f"Sample {sample_id} was not found in quarantine storage.")

        transfer = sandbox_controller.transfer_sample(sandbox_job, sample_path)
        started = sandbox_job["hypervisor"] and sandbox_controller.start_vm(sandbox_job)
        restored = sandbox_controller.restore_snapshot(sandbox_job)
        execution = sandbox_controller.execute_sample(sandbox_job, sample_path, timeout=120)
        telemetry = sandbox_controller.collect_telemetry(sandbox_job)
        pcap = sandbox_controller.save_pcap(sandbox_job)
        destroy = sandbox_controller.destroy_vm_session(sandbox_job)

        job = queue_manager.persist_job_status(
            job_id,
            status="completed",
            sandbox_job=sandbox_job,
            plan=plan,
            transfer=transfer,
            start=started,
            restore=restored,
            execute=execution,
            telemetry=telemetry,
            pcap=pcap,
            cleanup=destroy,
        )

        publish_telemetry(
            {
                "type": "job_status",
                "job_id": job_id,
                "status": "completed",
                "worker_id": self.request.hostname,
                "sample_id": sample_id,
                "filename": filename,
                "plan": plan,
            }
        )

        graph_stream.publish_node(
            "malware",
            sample_id,
            label=filename or sample_id,
            metadata={"sandbox_mode": network_mode},
        )

        return job
    except Exception as exc:
        job = queue_manager.retry_failed_job("sandbox_queue", job_id, reason=str(exc))
        publish_telemetry(
            {
                "type": "job_status",
                "job_id": job_id,
                "status": job["status"],
                "worker_id": self.request.hostname,
                "sample_id": sample_id,
                "filename": filename,
                "error": str(exc),
            }
        )
        raise


@celery_app.task(bind=True, name="backend.tasks.dispatch_ai_summary")
def dispatch_ai_summary(self, job_id, prompt, context=None):
    publish_telemetry(
        {
            "type": "job_status",
            "job_id": job_id,
            "status": "running",
            "worker_id": self.request.hostname,
            "prompt_snippet": prompt[:120],
        }
    )

    try:
        summary = ai_analyst.summarize(context or {"prompt": prompt})
        job = queue_manager.persist_job_status(
            job_id,
            status="completed",
            prompt=prompt,
            context=context,
            summary=summary,
        )

        publish_telemetry(
            {
                "type": "job_status",
                "job_id": job_id,
                "status": "completed",
                "worker_id": self.request.hostname,
                "summary": summary,
            }
        )

        graph_stream.publish_node(
            "ai",
            job_id,
            label="AI Summary",
            metadata={"prompt_snippet": prompt[:64]},
        )
        return summary
    except Exception as exc:
        job = queue_manager.retry_failed_job("ai_queue", job_id, reason=str(exc))
        publish_telemetry(
            {
                "type": "job_status",
                "job_id": job_id,
                "status": job["status"],
                "worker_id": self.request.hostname,
                "error": str(exc),
            }
        )
        raise
