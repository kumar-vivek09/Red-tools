# module/recon/tech_fingerprint.py

import asyncio
import ssl
import socket


class TechFingerprint:

    async def execute(self, target):

        technologies = []

        loop = asyncio.get_event_loop()

        headers = await loop.run_in_executor(
            None,
            self.fetch_headers,
            target
        )

        server = headers.get("server")
        powered_by = headers.get("x-powered-by")

        if server:
            technologies.append(server)

        if powered_by:
            technologies.append(powered_by)

        return {
            "technologies": technologies
        }

    def fetch_headers(self, target):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
                    ssock.send(request.encode())

                    response = ssock.recv(4096).decode(errors="ignore")

            headers = {}

            for line in response.split("\r\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            return headers

        except:
            return {}