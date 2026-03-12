import json
import os
from module.tools.tool_runner import ToolRunner


class MasscanEngine:

    async def run(self, target):

        output_file = "masscan_results.json"

        runner = ToolRunner()

        command = f"sudo masscan {target} -p1-10000 --rate=1000 -oJ {output_file}"

        await runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        with open(output_file) as f:
            data = json.load(f)

        ports = []

        for host in data:
            for port in host.get("ports", []):
                ports.append(port.get("port"))

        return ports