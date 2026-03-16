import subprocess
import json

class NucleiEngine:

    async def run(self, target):

        cmd = [
            "nuclei",
            "-u", f"http://{target}",
            "-json"
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        results = []

        for line in process.stdout.splitlines():
            try:
                results.append(json.loads(line))
            except:
                pass

        return results