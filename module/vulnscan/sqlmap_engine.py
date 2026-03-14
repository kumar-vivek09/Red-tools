from module.tools.tool_runner import ToolRunner


class SqlmapEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"sqlmap -u {target} --batch --crawl=1"

        await runner.run_command(command)

        return {"sqlmap": "scan completed"}