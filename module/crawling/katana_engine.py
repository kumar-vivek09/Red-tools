import subprocess

class KatanaEngine:

    async def run(self, target):

        cmd = [
            "katana",
            "-u", f"http://{target}",
            "-silent"
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        urls = process.stdout.strip().splitlines()

        return urls