from module.tools.tool_runner import ToolRunner


class AmassEngine:

    async def run(self, target):

        runner = ToolRunner()

        command = f"amass enum -d {target} -o amass_subdomains.txt"

        await runner.run_command(command)

        try:
            with open("amass_subdomains.txt") as f:
                subs = [line.strip() for line in f]
        except:
            subs = []

        return subs