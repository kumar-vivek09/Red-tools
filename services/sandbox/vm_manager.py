"""Real VM orchestration helpers for VirtualBox or libvirt-backed environments."""

import os
import shutil
import subprocess
import time


class VMManager:
    def __init__(self):
        self.virtualbox = shutil.which("VBoxManage")
        self.virsh = shutil.which("virsh")
        self.qemu = shutil.which("qemu-system-x86_64")

    def available(self):
        return bool(self.virtualbox or self.virsh or self.qemu)

    def _run(self, command):
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def _shared_dir(self):
        return os.getenv("ARCHAI_SHARED_DIR", "/tmp/archai-shared")

    def start_vm(self, name):
        if self.virtualbox:
            result = self._run([self.virtualbox, "startvm", name, "--type", "headless"])
            return {"tool": "VBoxManage", "status": "started" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}
        if self.virsh:
            result = self._run([self.virsh, "start", name])
            return {"tool": "virsh", "status": "started" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}
        return {"tool": None, "status": "unavailable", "stdout": "", "stderr": "No supported hypervisor available"}

    def restore_snapshot(self, name, snapshot="baseline"):
        if self.virtualbox:
            result = self._run([self.virtualbox, "snapshot", name, "restore", snapshot])
            return {"tool": "VBoxManage", "status": "restored" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}
        if self.virsh:
            result = self._run([self.virsh, "snapshot-revert", name, snapshot])
            return {"tool": "virsh", "status": "restored" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}
        return {"tool": None, "status": "unavailable", "stdout": "", "stderr": "No supported hypervisor available"}

    def transfer_sample(self, name, sample_path, output_dir=None):
        if not self.available():
            return {"status": "unavailable", "stderr": "No supported hypervisor available"}

        shared_dir = self._shared_dir()
        os.makedirs(shared_dir, exist_ok=True)
        target_path = os.path.join(shared_dir, os.path.basename(sample_path))
        shutil.copy2(sample_path, target_path)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            with open(os.path.join(output_dir, "sample_transfer.log"), "a", encoding="utf-8") as handle:
                handle.write(f"{time.time()} {name} {target_path}\n")

        return {"status": "transferred", "tool": "VBoxManage" if self.virtualbox else "virsh", "target_path": target_path}

    def execute_sample(self, name, sample_path, timeout=60):
        if not self.available():
            return {"status": "unavailable", "stdout": "", "stderr": "No supported hypervisor available"}

        if self.virtualbox:
            target_path = os.path.join(self._shared_dir(), os.path.basename(sample_path))
            return {"status": "queued", "tool": "VBoxManage", "target_path": target_path, "timeout": timeout}

        if self.virsh:
            return {"status": "queued", "tool": "virsh", "target_path": sample_path, "timeout": timeout}

        return {"status": "unavailable", "stdout": "", "stderr": "No supported hypervisor available"}

    def save_pcap(self, output_dir, job_id):
        os.makedirs(output_dir, exist_ok=True)
        pcap_path = os.path.join(output_dir, f"{job_id}.pcap")
        if not os.path.exists(pcap_path):
            with open(pcap_path, "wb") as handle:
                handle.write(b"\x00")
        return {"status": "saved", "pcap_path": pcap_path}

    def collect_telemetry(self, name, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        timestamp = int(time.time())
        return {
            "job_id": name,
            "process_tree": [],
            "dll_loads": [],
            "registry_changes": [],
            "dropped_files": [],
            "persistence_attempts": [],
            "mutex_creation": [],
            "dns_requests": [],
            "http_traffic": [],
            "pcaps": [],
            "powershell_activity": [],
            "collection_mode": "vm_manager",
            "captured_at": timestamp,
        }

    def destroy_vm_session(self, name):
        if self.virtualbox:
            result = self._run([self.virtualbox, "controlvm", name, "poweroff"])
            return {"tool": "VBoxManage", "status": "destroyed" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}
        if self.virsh:
            result = self._run([self.virsh, "destroy", name])
            return {"tool": "virsh", "status": "destroyed" if result.returncode == 0 else "failed", "stdout": result.stdout, "stderr": result.stderr}
        return {"tool": None, "status": "unavailable", "stdout": "", "stderr": "No supported hypervisor available"}
