from module.tools.tool_runner import ToolRunner

class GoWitnessEngine:

    def run(self, target):

        runner = ToolRunner()

        command = f"gowitness single http://{target}"

        result = runner.run_command(command)

        return result