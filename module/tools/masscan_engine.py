import subprocess

class MasscanEngine:

    async def run(self, target):

        cmd = [
            "sudo",
            "masscan",
            target,
            "-p1-65535",
            "--rate", "1000"
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            output = process.stdout

            ports = []

            for line in output.splitlines():
                if "open port" in line:
                    parts = line.split()
                    port = int(parts[2])
                    ports.append(port)

            return ports

        except Exception as e:
            print(f"[!] Masscan error: {e}")
            return []