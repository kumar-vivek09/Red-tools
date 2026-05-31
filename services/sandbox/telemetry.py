"""Sandbox telemetry ingestion helpers."""

import glob
import json
import os


class SandboxTelemetry:
    def collect(self, job_id, output_dir):
        telemetry = {
            "job_id": job_id,
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
            "collection_mode": "sandbox_logs",
        }

        if not os.path.isdir(output_dir):
            return telemetry

        for path in glob.glob(os.path.join(output_dir, "*.json")):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                if isinstance(payload, dict):
                    telemetry.update(payload)
            except Exception:
                continue

        telemetry["pcaps"] = glob.glob(os.path.join(output_dir, "*.pcap"))
        return telemetry
