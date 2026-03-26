from module.tools.tool_runner import ToolRunner
import os

class DalfoxEngine:

    async def run(self, target):

        print("[DEBUG] Running Dalfox...")

        runner = ToolRunner()

        output_file = "dalfox_results.txt"

        command = f"dalfox url http://{target} --silence --no-color --output {output_file}"

        await runner.run_command(command)

        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    return {"dalfox_output": f.read()}
        except Exception as e:
            return {"dalfox_error": str(e)}

        return {"dalfox_output": "Scan completed "}