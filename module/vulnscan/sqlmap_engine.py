import subprocess

class SqlmapEngine:

    async def run(self, target):

        cmd = [
            "sqlmap",
            "-u", f"http://{target}",
            "--batch",
            "--crawl=1",
            "--level=1",
            "--risk=1"
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            return {
                "sqlmap_output": process.stdout[:1000]
            }

        except Exception as e:
            return {"error": str(e)}