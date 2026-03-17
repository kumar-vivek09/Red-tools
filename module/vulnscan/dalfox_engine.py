import subprocess

class DalfoxEngine:

    async def run(self, target):

        cmd = [
            "dalfox",
            "url",
            f"http://{target}",
            "--silence"
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            return {
                "dalfox_output": process.stdout[:1000]
            }

        except Exception as e:
            return {"error": str(e)}