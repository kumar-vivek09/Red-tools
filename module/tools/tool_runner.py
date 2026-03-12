import asyncio


class ToolRunner:

    async def run_command(self, command):

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            return {
                "success": True,
                "stdout": stdout.decode(),
                "stderr": stderr.decode()
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }