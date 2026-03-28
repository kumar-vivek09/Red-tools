from module.tools.tool_runner import ToolRunner

class DalfoxEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"dalfox url http://{target} --silence"

        output = await runner.run_command(command)

        return {"dalfox_output": output[:1000] if output else "No output"}