"""High-level sandbox controller for disposable VM orchestration."""

import os
import uuid

from .telemetry import SandboxTelemetry
from .vm_manager import VMManager


class SandboxController:
    def __init__(self):
        self.vm_manager = VMManager()
        self.telemetry = SandboxTelemetry()
        self.output_root = os.getenv("SANDBOX_OUTPUT_DIR", "/tmp/archai-sandbox")

    def create_job(self, sample_metadata, network_mode="isolated"):
        job_id = uuid.uuid4().hex
        output_dir = os.path.join(self.output_root, job_id)
        os.makedirs(output_dir, exist_ok=True)
        return {
            "job_id": job_id,
            "sample_id": sample_metadata["sample_id"],
            "filename": sample_metadata["filename"],
            "status": "queued",
            "execution_mode": "disposable_vm",
            "snapshot_restore": True,
            "host_execution": False,
            "network_mode": network_mode,
            "fake_internet": network_mode != "blocked",
            "telemetry": [
                "process_tree",
                "dll_loads",
                "registry_changes",
                "dropped_files",
                "persistence_attempts",
                "mutex_creation",
                "dns_requests",
                "http_traffic",
                "pcap_capture",
                "powershell_activity",
            ],
            "required_tools": ["VirtualBox or KVM", "FakeNet-NG", "Sysmon", "Wireshark or tcpdump"],
            "hypervisor": self.vm_manager.available() and (self.vm_manager.virtualbox or self.vm_manager.virsh or self.vm_manager.qemu),
            "safe_mode": True,
            "cleanup_policy": "revert_snapshot_and_destroy",
            "output_dir": output_dir,
        }

    def plan_job(self, sandbox_job):
        hypervisor = self.vm_manager.available() and (self.vm_manager.virtualbox or self.vm_manager.virsh or self.vm_manager.qemu)
        if not hypervisor:
            return {
                "status": "pending",
                "reason": "No supported hypervisor is available in this environment.",
                "hypervisor": None,
            }

        return {
            "status": "ready",
            "hypervisor": hypervisor,
            "snapshot_restore": True,
            "fake_internet": sandbox_job.get("fake_internet", True),
            "isolation": sandbox_job.get("network_mode", "isolated"),
        }

    def start_vm(self, sandbox_job):
        return self.vm_manager.start_vm(sandbox_job["sample_id"])

    def restore_snapshot(self, sandbox_job):
        return self.vm_manager.restore_snapshot(sandbox_job["sample_id"])

    def transfer_sample(self, sandbox_job, sample_path):
        if not sample_path:
            return {"status": "pending", "reason": "No sample path provided"}
        return self.vm_manager.transfer_sample(sandbox_job["sample_id"], sample_path, sandbox_job.get("output_dir"))

    def execute_sample(self, sandbox_job, sample_path, timeout=60):
        return self.vm_manager.execute_sample(sandbox_job["sample_id"], sample_path, timeout=timeout)

    def collect_telemetry(self, sandbox_job):
        return self.telemetry.collect(sandbox_job["job_id"], sandbox_job.get("output_dir", self.output_root))

    def save_pcap(self, sandbox_job):
        return self.vm_manager.save_pcap(sandbox_job.get("output_dir", self.output_root), sandbox_job["job_id"])

    def destroy_vm_session(self, sandbox_job):
        return self.vm_manager.destroy_vm_session(sandbox_job["sample_id"])
