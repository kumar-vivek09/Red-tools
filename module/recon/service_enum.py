# module/recon/service_enum.py

class ServiceEnum:

    PORT_SERVICE_MAP = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }

    async def execute(self, target):
        """
        This module no longer performs independent scanning.
        Services will be derived from open_ports inside orchestrator.
        Keeping this module for architectural consistency.
        """
        return {}