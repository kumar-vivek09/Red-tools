from module.tools.tool_runner import ToolRunner


class KatanaEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"katana -u {target} -silent -o katana_urls.txt"

        await runner.run_command(command)

        try:
            with open("katana_urls.txt") as f:
                urls = [line.strip() for line in f]
        except:
            urls = []

        return urls