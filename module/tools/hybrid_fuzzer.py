import asyncio
import json
import os

class HybridFuzzer:

    async def run(self, target):

        print("[AI] Starting Hybrid Fuzzing (Ferox + Dirsearch)")

        ferox_output = "ferox.json"
        dirsearch_output = "dirsearch.json"

        results = []

        # =========================
        # 1. FERORBUSTER (FAST)
        # =========================
        print("[DEBUG] Running Feroxbuster...")

        ferox_cmd = [
            "feroxbuster",
            "-u", f"http://{target}",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "--json",
            "-o", ferox_output,
            "-t", "50"
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *ferox_cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
        except Exception as e:
            print("[FEROX ERROR]", e)

        # =========================
        # PARSE FEROX
        # =========================
        if os.path.exists(ferox_output):
            try:
                with open(ferox_output) as f:
                    for line in f:
                        data = json.loads(line)
                        results.append(data.get("url"))
            except:
                pass

        # =========================
        # 2. DIRSEARCH (DEEP)
        # =========================
        print("[DEBUG] Running Dirsearch...")

        dir_cmd = [
            "python3",
            "dirsearch/dirsearch.py",
            "-u", f"http://{target}",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "--json-report", dirsearch_output,
            "-t", "30"
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *dir_cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
        except Exception as e:
            print("[DIRSEARCH ERROR]", e)

        # =========================
        # PARSE DIRSEARCH
        # =========================
        if os.path.exists(dirsearch_output):
            try:
                with open(dirsearch_output) as f:
                    data = json.load(f)
                    for item in data.get("results", []):
                        results.append(item.get("url"))
            except:
                pass

        # =========================
        # CLEAN RESULTS
        # =========================
        results = list(set(filter(None, results)))

        print(f"[AI] Total endpoints discovered: {len(results)}")

        return results