import subprocess
import json

class WhatWebEngine:

    async def run(self, target):

        cmd = [
            "whatweb",
            f"http://{target}",
            "--log-json=whatweb.json"
        ]

        subprocess.run(cmd, capture_output=True)

        try:
            with open("whatweb.json") as f:
                data = json.load(f)

            return data

        except Exception:
            return {}