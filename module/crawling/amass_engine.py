import subprocess

class AmassEngine:

    async def run(self, target):

        cmd = [
            "amass",
            "enum",
            "-d", target
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            subdomains = process.stdout.splitlines()

            return subdomains

        except Exception as e:
            return []