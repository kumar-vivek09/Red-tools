import subprocess

class NiktoEngine:

    async def run(self, target):

        cmd = [
            "nikto",
            "-h", f"http://{target}"
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            return {
                "nikto_output": process.stdout[:1000]  # limit output
            }

        except Exception as e:
            return {"error": str(e)}