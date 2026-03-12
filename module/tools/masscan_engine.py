from module.tools.tool_runner import ToolRunner

class MasscanEngine:

    def run(self, target):

        runner = ToolRunner()

        command = f"masscan {target} -p1-65535 --rate=1000 -oJ masscan_results.json"

        result = runner.run_command(command)

        return result