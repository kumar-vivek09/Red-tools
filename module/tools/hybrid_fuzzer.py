import subprocess
import os

class HybridFuzzer:

    def run(self, target):
        results = []

        wordlist = "/usr/share/wordlists/dirb/common.txt"

        ferox_output = "ferox.txt"
        dirsearch_output = "dirsearch.txt"

        print("[DEBUG] Starting Feroxbuster...")

        try:
            subprocess.run(
                f"feroxbuster -u http://{target} -w {wordlist} -o {ferox_output} --silent",
                shell=True,
                timeout=120
            )
        except Exception as e:
            print("[ERROR] Ferox:", e)

        print("[DEBUG] Starting Dirsearch...")

        try:
            subprocess.run(
                f"python3 dirsearch/dirsearch.py -u http://{target} -w {wordlist} -o {dirsearch_output} --quiet",
                shell=True,
                timeout=120
            )
        except Exception as e:
            print("[ERROR] Dirsearch:", e)

        # ===== PARSE OUTPUT =====
        if os.path.exists(ferox_output):
            with open(ferox_output, "r") as f:
                for line in f:
                    if "200" in line or "301" in line or "302" in line:
                        results.append(line.strip())

        if os.path.exists(dirsearch_output):
            with open(dirsearch_output, "r") as f:
                for line in f:
                    if "200" in line or "403" in line:
                        results.append(line.strip())

        if not results:
            print("[INFO] No fuzzing results found")
            return []

        return list(set(results))