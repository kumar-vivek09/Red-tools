import subprocess
import json

class WhatWebEngine:

    async def run(self, target):

        cmd = [
            "whatweb",
            f"http://{target}",
            "--log-json=whatweb.json"
        ]

        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        try:
            with open("whatweb.json") as f:
                data = json.load(f)

            if isinstance(data, list) and len(data) > 0:
                return data[0]

            return {}

        except:
            return {}