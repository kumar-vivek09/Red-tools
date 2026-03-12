import json
import os
from module.tools.tool_runner import ToolRunner


class NucleiEngine:

    def run(self, target):

        output_file = "nuclei_results.json"

        runner = ToolRunner()

        command = f"nuclei -u {target} -json -o {output_file}"

        runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        return self.parse_results(output_file)

    def parse_results(self, file):

        findings = []

        with open(file) as f:
            for line in f:
                try:
                    data = json.loads(line)

                    findings.append({
                        "template": data.get("templateID"),
                        "severity": data.get("info", {}).get("severity"),
                        "name": data.get("info", {}).get("name"),
                        "matched": data.get("matched-at")
                    })

                except:
                    continue

        return findings