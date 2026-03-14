from module.tools.tool_runner import ToolRunner


class AssetfinderEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"assetfinder --subs-only {target} > assetfinder_subdomains.txt"

        await runner.run_command(command)

        try:
            with open("assetfinder_subdomains.txt") as f:
                subs = [line.strip() for line in f]
        except:
            subs = []

        return subs