import json
import os
from module.tools.tool_runner import ToolRunner


class NucleiEngine:

    async def run(self, target):

        output_file = "nuclei_results.json"

        runner = ToolRunner()

        command = f"nuclei -u {target} -json -o {output_file} -rate-limit 100"

        await runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        findings = []

        with open(output_file) as f:
            for line in f:
                try:
                    data = json.loads(line)

                    findings.append({
                        "template": data.get("templateID"),
                        "severity": data.get("info", {}).get("severity"),
                        "name": data.get("info", {}).get("name")
                    })

                except:
                    continue

        return findings