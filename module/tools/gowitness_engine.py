from module.tools.tool_runner import ToolRunner


class GoWitnessEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"gowitness single http://{target}"

        await runner.run_command(command)

        return {
            "screenshot": f"http://{target}"
        }