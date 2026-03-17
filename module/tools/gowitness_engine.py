import subprocess

class GoWitnessEngine:

    async def run(self, target):

        cmd = [
            "gowitness",
            "scan",
            "single",
            "--url", f"http://{target}",
            "--quiet"
        ]

        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            return {
                "screenshot": f"http://{target}"
            }

        except Exception as e:
            return {"error": str(e)}