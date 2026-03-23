import subprocess

class MasscanEngine:

    async def run(self, target):

        print("[DEBUG] Running Masscan...")

        cmd = [
            "sudo",
            "masscan",
            target,
            "-p80,443,22",
            "--rate", "1000"
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            print("[DEBUG] Masscan finished")

            output = process.stdout
            ports = []

            for line in output.splitlines():
                if "open port" in line:
                    parts = line.split()
                    ports.append(int(parts[2]))

            print(f"[DEBUG] Masscan ports: {ports}")

            return ports

        except Exception as e:
            print(f"[ERROR] Masscan failed: {e}")
            return []