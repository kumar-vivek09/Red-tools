import asyncio

class ToolRunner:

    async def run_command(self, command):

        print(f"[LIVE] Running: {command}")

        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )

        while True:
            line = await process.stdout.readline()
            if not line:
                break
            print(line.decode().strip())

        await process.wait()

        print(f"[DONE] {command}")