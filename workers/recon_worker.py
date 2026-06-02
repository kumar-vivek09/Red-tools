import asyncio
import os
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.graph_stream import GraphStream
from services.queue import QueueManager
from services.reports.report_service import ReportService
from services.recon.service import ReconService


class NativeReconWorker:
    def __init__(self):
        self.worker_id = os.getenv("WORKER_ID") or os.getenv("ARCHAI_WORKER_ID") or f"kali-recon-{uuid.uuid4().hex[:6]}"
        self.worker_role = os.getenv("WORKER_ROLE") or "recon"
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.queue_manager = QueueManager(redis_url=self.redis_url)
        self.recon_service = ReconService()
        self.report_service = ReportService()
        self.graph_stream = GraphStream(self.queue_manager)

    def log(self, message, *extra):
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        suffix = " ".join(map(str, extra))
        print(f"[{timestamp}] [worker:{self.worker_id}] {message} {suffix}".strip())

    async def publish_status(self, job_id, status, **metadata):
        payload = {
            "type": "job_status",
            "job_id": job_id,
            "status": status,
            "worker_id": self.worker_id,
            "queue": "recon_queue",
            **metadata,
        }
        self.queue_manager.persist_job_status(job_id, status, **metadata)
        await self.queue_manager.publish_async("telemetry", payload)
        await self.queue_manager.publish_async("telemetry.recon", payload)
        return payload

    async def publish_telemetry(self, event_type, job_id, **payload):
        event = {
            "type": "telemetry",
            "event_type": event_type,
            "job_id": job_id,
            "worker_id": self.worker_id,
            "timestamp": int(time.time()),
            **payload,
        }
        await self.queue_manager.publish_async("telemetry", event)
        await self.queue_manager.publish_async("telemetry.recon", event)
        return event

    async def register(self):
        self.queue_manager.register_worker(
            self.worker_id,
            capabilities=["recon"],
            metadata={
                "worker_role": self.worker_role,
                "status": "online",
                "redis_url": self.redis_url,
            },
        )
        await self.publish_telemetry("worker_registered", self.worker_id, worker_role=self.worker_role, capabilities=["recon"])

    async def heartbeat_loop(self):
        while True:
            self.queue_manager.worker_heartbeat(
                self.worker_id,
                metadata={
                    "worker_role": self.worker_role,
                    "capabilities": ["recon"],
                    "status": "online",
                    "redis_url": self.redis_url,
                },
            )
            self.log(f"heartbeat published backend={self.queue_manager._backend()}")
            await asyncio.sleep(15)

    async def consume(self):
        while True:
            task = self.queue_manager.dequeue("recon_queue")
            if task is None:
                await asyncio.sleep(1)
                continue

            task["worker_id"] = self.worker_id
            self.queue_manager.set_job(task["job_id"], task)
            self.log(f"job claimed job_id={task['job_id']} target={task.get('target')}")
            asyncio.create_task(self.process_job(task))

    async def run_shell(self, command, timeout=600):
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    subprocess.run,
                    command,
                    capture_output=True,
                    text=True,
                ),
                timeout=timeout,
            )
            return {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except FileNotFoundError as exc:
            return {
                "command": command,
                "returncode": None,
                "stdout": "",
                "stderr": str(exc),
                "available": False,
            }
        except asyncio.TimeoutError:
            return {
                "command": command,
                "returncode": None,
                "stdout": "",
                "stderr": "timeout",
                "timed_out": True,
            }

    async def execute_native_tools(self, target, job_id):
        native_results = {}

        def ensure_url(value):
            if value.startswith(("http://", "https://")):
                return value
            return f"http://{value}"

        nmap_path = shutil.which("nmap")
        if nmap_path:
            nmap_result = await self.run_shell([nmap_path, "-Pn", "-T4", "--top-ports", "100", target, "-oX", "-"], timeout=600)
            native_results["nmap"] = nmap_result
            if nmap_result.get("stdout"):
                try:
                    root = ET.fromstring(nmap_result["stdout"])
                    for host in root.findall("host"):
                        address = host.find("address")
                        hostname = address.attrib.get("addr") if address is not None else None
                        if not hostname:
                            continue
                        await self.publish_telemetry("host_discovered", job_id, host=hostname, target=target)
                        self.graph_stream.publish_node(
                            "attack",
                            hostname,
                            label=hostname,
                            metadata={"kind": "host", "source": "nmap", "target": target, "job_id": job_id},
                        )

                        ports = host.find("ports")
                        if ports is None:
                            continue
                        for port in ports.findall("port"):
                            state = port.find("state")
                            if state is None or state.attrib.get("state") != "open":
                                continue
                            port_id = port.attrib.get("portid")
                            service = port.find("service")
                            service_name = service.attrib.get("product") if service is not None else None
                            service_version = service.attrib.get("version") if service is not None else None
                            if port_id:
                                port_node_id = f"{hostname}:{port_id}"
                                await self.publish_telemetry(
                                    "port_discovered",
                                    job_id,
                                    host=hostname,
                                    port=int(port_id),
                                    service=service_name,
                                    version=service_version,
                                    target=target,
                                )
                                self.graph_stream.publish_node(
                                    "attack",
                                    port_node_id,
                                    label=port_node_id,
                                    metadata={
                                        "kind": "port",
                                        "host": hostname,
                                        "port": int(port_id),
                                        "service": service_name,
                                        "version": service_version,
                                        "source": "nmap",
                                        "job_id": job_id,
                                    },
                                )
                                self.graph_stream.publish_edge(
                                    "attack",
                                    f"edge:{hostname}:{port_id}",
                                    hostname,
                                    port_node_id,
                                    "listens_on",
                                    metadata={"job_id": job_id},
                                )
                                if service_name:
                                    await self.publish_telemetry(
                                        "service_detected",
                                        job_id,
                                        host=hostname,
                                        port=int(port_id),
                                        service=service_name,
                                        version=service_version,
                                        target=target,
                                    )
                except ET.ParseError as exc:
                    await self.publish_telemetry("scan_failed", job_id, target=target, error=f"nmap_parse_failed: {exc}")
        else:
            native_results["nmap"] = {"available": False, "stderr": "nmap not found"}

        masscan_path = shutil.which("masscan")
        if masscan_path:
            masscan_result = await self.run_shell([masscan_path, "-p80,443,22", "--rate", "1000", target], timeout=600)
            native_results["masscan"] = masscan_result
            for line in masscan_result.get("stdout", "").splitlines():
                if "Discovered open port" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        port = int(parts[2])
                        host = parts[3].strip("().")
                        await self.publish_telemetry("port_discovered", job_id, host=host, port=port, tool="masscan", target=target)
                        self.graph_stream.publish_node(
                            "attack",
                            f"{host}:{port}",
                            label=f"{host}:{port}",
                            metadata={"kind": "port", "source": "masscan", "host": host, "port": port, "job_id": job_id},
                        )
                        self.graph_stream.publish_edge(
                            "attack",
                            f"edge:{host}:{port}",
                            host,
                            f"{host}:{port}",
                            "listens_on",
                            metadata={"job_id": job_id},
                        )
        else:
            native_results["masscan"] = {"available": False, "stderr": "masscan not found"}

        assetfinder_path = shutil.which("assetfinder")
        if assetfinder_path:
            assetfinder_result = await self.run_shell([assetfinder_path, "--subs-only", target], timeout=600)
            native_results["assetfinder"] = assetfinder_result
            for line in assetfinder_result.get("stdout", "").splitlines():
                subdomain = line.strip()
                if subdomain:
                    await self.publish_telemetry("host_discovered", job_id, host=subdomain, target=target, tool="assetfinder")
                    self.graph_stream.publish_node(
                        "attack",
                        subdomain,
                        label=subdomain,
                        metadata={"kind": "host", "source": "assetfinder", "target": target, "job_id": job_id},
                    )
        else:
            native_results["assetfinder"] = {"available": False, "stderr": "assetfinder not found"}

        katana_path = shutil.which("katana")
        if katana_path:
            katana_result = await self.run_shell([katana_path, "-u", ensure_url(target), "-silent"], timeout=600)
            native_results["katana"] = katana_result
            for line in katana_result.get("stdout", "").splitlines():
                url = line.strip()
                if url:
                    await self.publish_telemetry("url_discovered", job_id, url=url, target=target, tool="katana")
                    self.graph_stream.publish_node(
                        "attack",
                        f"url:{url}",
                        label=url,
                        metadata={"kind": "url", "source": "katana", "target": target, "job_id": job_id},
                    )
                    host = url.split("//", 1)[-1].split("/", 1)[0]
                    self.graph_stream.publish_edge(
                        "attack",
                        f"edge:{host}:{url}",
                        host,
                        f"url:{url}",
                        "hosts",
                        metadata={"job_id": job_id},
                    )
        else:
            native_results["katana"] = {"available": False, "stderr": "katana not found"}

        whatweb_path = shutil.which("whatweb")
        if whatweb_path:
            whatweb_result = await self.run_shell([whatweb_path, ensure_url(target)], timeout=600)
            native_results["whatweb"] = whatweb_result
            for line in whatweb_result.get("stdout", "").splitlines():
                if line.strip():
                    await self.publish_telemetry("service_detected", job_id, target=target, service=line.strip(), tool="whatweb")
        else:
            native_results["whatweb"] = {"available": False, "stderr": "whatweb not found"}

        dalfox_path = shutil.which("dalfox")
        if dalfox_path:
            dalfox_result = await self.run_shell([dalfox_path, "url", ensure_url(target), "--silence"], timeout=600)
            native_results["dalfox"] = dalfox_result
            for line in dalfox_result.get("stdout", "").splitlines():
                if "[VULNERABILITY]" in line or "vulnerab" in line.lower():
                    await self.publish_telemetry("vulnerability_detected", job_id, target=target, details=line.strip(), tool="dalfox")
        else:
            native_results["dalfox"] = {"available": False, "stderr": "dalfox not found"}

        gowitness_path = shutil.which("gowitness")
        if gowitness_path:
            gowitness_result = await self.run_shell([gowitness_path, "scan", "--url", ensure_url(target)], timeout=600)
            native_results["gowitness"] = gowitness_result
        else:
            native_results["gowitness"] = {"available": False, "stderr": "gowitness not found"}

        return native_results

    async def process_job(self, job):
        job_id = job["job_id"]
        target = job["target"]
        scan_level = int(job.get("scan_level", 1))

        try:
            self.log(f"DEBUG: starting publish_status running job_id={job_id}")
            await self.publish_status(job_id, "running", target=target, scan_level=scan_level, stage="recon")
            self.log(f"DEBUG: publish_status running completed job_id={job_id}")
            await self.publish_telemetry("scan_started", job_id, target=target, scan_level=scan_level)

            self.log(f"DEBUG: starting execute_native_tools job_id={job_id}")
            try:
                native_results = await self.execute_native_tools(target, job_id)
            except Exception as exc:
                self.log(f"DEBUG: execute_native_tools failed: {exc}")
                raise
            self.log(f"DEBUG: execute_native_tools completed job_id={job_id}")

            self.log(f"DEBUG: starting recon_service.scan_async job_id={job_id}")
            try:
                scan_result = await self.recon_service.scan_async(target)
            except Exception as exc:
                self.log(f"DEBUG: recon_service.scan_async failed: {exc}")
                raise
            self.log(f"DEBUG: recon_service.scan_async completed job_id={job_id}")

            combined_results = dict(scan_result)
            combined_results["native_results"] = native_results

            self.log(f"DEBUG: starting generate_json_report job_id={job_id}")
            report_file = self.report_service.generate_json_report(target, combined_results)
            self.log(f"DEBUG: generate_json_report completed job_id={job_id}")

            self.log(f"DEBUG: starting persist_job_status job_id={job_id}")
            self.queue_manager.persist_job_status(
                job_id,
                status="completed",
                target=target,
                scan_level=scan_level,
                stage="recon",
                report_file=report_file,
                native_results=native_results,
                result=combined_results,
            )
            self.log(f"DEBUG: persist_job_status completed job_id={job_id}")
            await self.publish_status(
                job_id,
                "completed",
                target=target,
                scan_level=scan_level,
                stage="recon",
                report_file=report_file,
                native_results=native_results,
                result=combined_results,
            )
            await self.publish_telemetry("scan_completed", job_id, target=target, report_file=report_file, tool_count=len(native_results))
            self.graph_stream.publish_node(
                "attack",
                target,
                label=target,
                metadata={"kind": "host", "source": "native", "target": target, "job_id": job_id},
            )

            attack_paths = combined_results.get("attack_paths") or []
            for index, path in enumerate(attack_paths[:10]):
                if isinstance(path, dict) and path.get("source") and path.get("target"):
                    self.graph_stream.publish_edge(
                        "attack",
                        f"edge:{job_id}:{index}",
                        path["source"],
                        path["target"],
                        path.get("relation", "related"),
                        metadata={"job_id": job_id, "index": index},
                    )

            self.log(f"job completed job_id={job_id} report_file={report_file}")
        except Exception as exc:
            self.queue_manager.persist_job_status(job_id, status="failed", error=str(exc), target=target)
            await self.publish_status(job_id, "failed", target=target, error=str(exc))
            await self.publish_telemetry("scan_failed", job_id, target=target, error=str(exc))
            self.log(f"job failed job_id={job_id} error={exc}")

    async def run(self):
        self.log(f"starting remote recon worker redis={self.redis_url}")
        await self.register()
        await asyncio.gather(self.heartbeat_loop(), self.consume())


async def main():
    worker = NativeReconWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
