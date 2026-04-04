import subprocess

class HarvesterEngine:

    async def run(self, target):

        cmd = [
            "theHarvester",
            "-d", target,
            "-b", "crtsh,rapiddns,otx,virustotal,shodan,censys,zoomeye,dnsdumpster,criminalip,fullhunt"
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            return process.stdout

        except Exception as e:
            return f"Harvester error: {str(e)}"