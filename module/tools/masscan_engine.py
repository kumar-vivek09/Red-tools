import json
import os
from module.tools.tool_runner import ToolRunner


class MasscanEngine:

    def run(self, target):

        output_file = "masscan_results.json"

        runner = ToolRunner()

        command = f"masscan {target} -p1-65535 --rate=1000 -oJ {output_file}"

        runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        return self.parse_results(output_file)

    def parse_results(self, file):

        with open(file) as f:
            data = json.load(f)

        ports = []

        for host in data:
            for port in host.get("ports", []):
                ports.append(port.get("port"))

        return ports