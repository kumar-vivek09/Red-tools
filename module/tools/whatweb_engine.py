import subprocess
import json
import os

class WhatWebEngine:

    async def run(self, target):

        output_file = "whatweb.json"

        cmd = [
            "whatweb",
            f"http://{target}",   # ✅ FIXED
            "--log-json", output_file
        ]

        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                return data
        except Exception as e:
            return str(e)

        return {}