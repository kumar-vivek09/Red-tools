import json
import os
from module.tools.tool_runner import ToolRunner


class WhatWebEngine:

    async def run(self, target):

        runner = ToolRunner()

        output_file = "whatweb_result.json"

        command = f"whatweb {target} --log-json={output_file}"

        await runner.run_command(command)

        if not os.path.exists(output_file):
            return []

        with open(output_file) as f:
            data = json.load(f)

        tech = []

        for entry in data:
            for plugin in entry.get("plugins", {}):
                tech.append(plugin)

        return tech