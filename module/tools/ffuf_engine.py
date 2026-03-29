import asyncio
import json

class FfufEngine:

    async def run(self, target):

        print("[DEBUG] Starting FFUF scan...")

        output_file = "ffuf_output.json"

        cmd = [
            "ffuf",
            "-u", f"http://{target}/FUZZ",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-mc", "200,301,302",
            "-of", "json",
            "-o", output_file,
            "-t", "40"
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                print("[FFUF ERROR]", stderr.decode())
                return []

        except Exception as e:
            print("[FFUF FAILED]", str(e))
            return []

        # ---------------------------
        # PARSE OUTPUT
        # ---------------------------
        try:
            with open(output_file) as f:
                data = json.load(f)

            results = []

            for item in data.get("results", []):
                results.append({
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length")
                })

            print(f"[DEBUG] FFUF found {len(results)} endpoints")

            return results

        except Exception as e:
            print("[FFUF PARSE ERROR]", str(e))
            return []