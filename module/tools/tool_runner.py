import asyncio
import subprocess

class ToolRunner:

    async def run_command(self, command):

        print(f"[DEBUG] Executing: {command}")

        process = await asyncio.create_subprocess_shell(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        await process.communicate()

        print(f"[DEBUG] Finished: {command}")