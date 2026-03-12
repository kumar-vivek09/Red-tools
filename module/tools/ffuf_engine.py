import json
import os
from module.tools.tool_runner import ToolRunner


class FfufEngine:

    def run(self, target):

        output_file = "ffuf_output.json"

        runner = ToolRunner()

        command = f"ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o {output_file} -of json"

        runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        return self.parse_results(output_file)

    def parse_results(self, file):

        with open(file) as f:
            data = json.load(f)

        endpoints = []

        for r in data.get("results", []):
            endpoints.append({
                "endpoint": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length")
            })

        return endpoints