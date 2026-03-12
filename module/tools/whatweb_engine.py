from module.tools.tool_runner import ToolRunner

class WhatWebEngine:

    def run(self, target):

        runner = ToolRunner()

        command = f"whatweb {target} --log-json whatweb_result.json"

        result = runner.run_command(command)

        return result