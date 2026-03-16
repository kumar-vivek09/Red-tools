import subprocess
import json

class FfufEngine:

    async def run(self, target):

        cmd = [
            "ffuf",
            "-u", f"http://{target}/FUZZ",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-of", "json"
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        try:
            data = json.loads(process.stdout)

            results = [
                r["url"] for r in data.get("results", [])
            ]

            return results

        except Exception:
            return []