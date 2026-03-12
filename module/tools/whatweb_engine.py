import json
import os
from module.tools.tool_runner import ToolRunner


class WhatWebEngine:

    def run(self, target):

        output_file = "whatweb_result.json"

        runner = ToolRunner()

        command = f"whatweb {target} --log-json={output_file}"

        runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        return self.parse_results(output_file)

    def parse_results(self, file):

        with open(file) as f:
            data = json.load(f)

        technologies = []

        for entry in data:
            for plugin in entry.get("plugins", {}):
                technologies.append(plugin)

        return technologies