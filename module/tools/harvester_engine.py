from module.tools.tool_runner import ToolRunner


class HarvesterEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"theHarvester -d {target} -b all -f harvester_results"

        await runner.run_command(command)

        return {
            "osint": "harvester scan completed"
        }