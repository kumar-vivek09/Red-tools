from module.tools.tool_runner import ToolRunner


class DalfoxEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"dalfox url {target} --output dalfox_results.txt"

        await runner.run_command(command)

        return {"dalfox": "scan completed"}