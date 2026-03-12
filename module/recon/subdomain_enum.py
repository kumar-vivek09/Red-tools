# module/recon/subdomain_enum.py

import asyncio
import socket


class SubdomainEnum:

    COMMON_SUBDOMAINS = [
        "www",
        "api",
        "admin",
        "mail",
        "dev",
        "test"
    ]

    async def execute(self, target):

        found = []

        loop = asyncio.get_event_loop()

        for sub in self.COMMON_SUBDOMAINS:
            domain = f"{sub}.{target}"

            exists = await loop.run_in_executor(
                None,
                self.check_dns,
                domain
            )

            if exists:
                found.append(domain)

        return {
            "subdomains": found
        }

    def check_dns(self, domain):
        try:
            socket.gethostbyname(domain)
            return True
        except:
            return False