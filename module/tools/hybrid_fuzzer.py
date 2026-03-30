import subprocess
import os

class HybridFuzzer:

    def run(self, target):
        results = []

        wordlist = "/usr/share/wordlists/dirb/common.txt"
        output_file = "ferox.txt"

        url = f"http://{target}"

        print("[DEBUG] Running Feroxbuster...")

        try:
            subprocess.run(
                f"feroxbuster -u {url} -w {wordlist} -o {output_file} -t 50 -d 2",
                shell=True
            )
        except Exception as e:
            print("[ERROR] Ferox:", e)
            return []

        # Parse results
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    if "200" in line or "301" in line or "302" in line:
                        results.append(line.strip())

        if not results:
            print("[INFO] No endpoints found")
            return []

        return list(set(results))