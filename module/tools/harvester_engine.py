from module.tools.tool_runner import ToolRunner

class HarvesterEngine:

    def run(self, target):

        runner = ToolRunner()

        command = f"theHarvester -d {target} -b all -f harvester_results"

        result = runner.run_command(command)

        return result