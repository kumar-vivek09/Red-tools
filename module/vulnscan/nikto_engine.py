from module.tools.tool_runner import ToolRunner

class NiktoEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"nikto -h http://{target} -maxtime 60"

        output = await runner.run_command(command)

        return {"nikto_output": output[:1000] if output else "No output"}