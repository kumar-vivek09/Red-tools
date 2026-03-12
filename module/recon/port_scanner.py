# module/recon/port_scanner.py

import socket
import asyncio


class PortScanner:

    async def execute(self, target, ports=[21, 22, 80, 443, 8080]):

        open_ports = []

        loop = asyncio.get_event_loop()

        for port in ports:
            result = await loop.run_in_executor(
                None,
                self.check_port,
                target,
                port
            )

            if result:
                open_ports.append(port)

        return {
            "open_ports": open_ports,
            "risk_score": len(open_ports) * 1.5
        }

    def check_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((target, port))
            sock.close()

            return result == 0

        except:
            return False