import subprocess

class AssetfinderEngine:

    def run(self, target):
        print("[DEBUG] Running Assetfinder...")

        try:
            result = subprocess.check_output(
                f"assetfinder --subs-only {target}",
                shell=True
            ).decode().splitlines()

            if not result:
                print("[INFO] No subdomains found, using fallback")
                return [target]

            return result

        except Exception as e:
            print("[ERROR] Assetfinder:", e)
            return [target]