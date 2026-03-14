from module.tools.tool_runner import ToolRunner


class NiktoEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"nikto -h {target} -output nikto_results.txt"

        await runner.run_command(command)

        return {"nikto": "scan completed"}