import os
from module.tools.tool_runner import ToolRunner


class HarvesterEngine:

    def run(self, target):

        runner = ToolRunner()

        output_file = "harvester_results.json"

        command = f"theHarvester -d {target} -b all -f harvester_results"

        runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        return {"osint": "harvester scan completed"}