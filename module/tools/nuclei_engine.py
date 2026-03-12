from module.tools.tool_runner import ToolRunner

class NucleiEngine:

    def run(self, target):

        runner = ToolRunner()

        command = f"nuclei -u {target} -json -o nuclei_results.json"

        result = runner.run_command(command)

        return result