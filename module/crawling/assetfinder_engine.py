import subprocess

class AssetfinderEngine:

    async def run(self, target):

        cmd = ["assetfinder", "--subs-only", target]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        output = process.stdout.strip().splitlines()

        return output