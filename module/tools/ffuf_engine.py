from module.tools.tool_runner import ToolRunner

class FfufEngine:

    def run(self, target):

        runner = ToolRunner()

        command = f"ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o ffuf_output.json"

        result = runner.run_command(command)

        return result