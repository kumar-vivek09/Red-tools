import json
import os
from module.tools.tool_runner import ToolRunner


class FfufEngine:

    async def run(self, target):

        runner = ToolRunner()

        output_file = "ffuf_output.json"

        command = f"ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o {output_file} -of json -t 40"

        await runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        with open(output_file) as f:
            data = json.load(f)

        results = []

        for r in data.get("results", []):
            results.append({
                "endpoint": r.get("url"),
                "status": r.get("status"),
                "length": r.get("length")
            })

        return results