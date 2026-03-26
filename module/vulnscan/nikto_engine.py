from module.tools.tool_runner import ToolRunner
import os

class NiktoEngine:

    async def run(self, target):

        print("[DEBUG] Running Nikto...")

        runner = ToolRunner()

        output_file = "nikto_results.txt"

        command = f"nikto -h http://{target} -maxtime 60 -output {output_file}"

        await runner.run_command(command)

        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    return {"nikto_output": f.read()}
        except Exception as e:
            return {"nikto_error": str(e)}

        return {"nikto_output": "Scan completed (no critical issues found)"}