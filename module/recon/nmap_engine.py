import subprocess
import xml.etree.ElementTree as ET
import os
import platform
import shutil


class NmapEngine:

    def __init__(self, scan_level=1):
        self.scan_level = scan_level


    # --------------------------------------------------
    # FULL TARGET SCAN
    # --------------------------------------------------
    async def execute(self, target):

        output_file = "nmap_scan.xml"
        cmd = self.build_command(target, output_file)

        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=600
            )

        except subprocess.TimeoutExpired:

            print("[!] Nmap scan timed out")

            if platform.system() == "Windows":
                subprocess.run(
                    ["taskkill", "/F", "/IM", "nmap.exe"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                subprocess.run(
                    ["pkill", "-f", "nmap"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

            return self.empty_result()

        if not os.path.exists(output_file):
            return self.empty_result()

        return self.parse_xml(output_file)


    # --------------------------------------------------
    # MASSCAN → NMAP TARGETED SCAN
    # --------------------------------------------------
    async def execute_ports(self, target, ports):

        if not ports:
            return await self.execute(target)

        output_file = "nmap_scan.xml"
        port_string = ",".join(map(str, ports))

        if platform.system() == "Windows":
            base_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        else:
            base_path = shutil.which("nmap") or "nmap"

        cmd = [
            base_path,
            "-sV",
            "-p",
            port_string,
            "-T4",
            target,
            "-oX",
            output_file
        ]

        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=600
            )

        except subprocess.TimeoutExpired:
            return self.empty_result()

        if not os.path.exists(output_file):
            return self.empty_result()

        return self.parse_xml(output_file)


    # --------------------------------------------------
    # DEFAULT RESULT STRUCTURE
    # --------------------------------------------------
    def empty_result(self):
        return {
            "open_ports": [],
            "technologies": [],
            "os_detection": None,
            "risk_score": 0
        }


    # --------------------------------------------------
    # BUILD NMAP COMMAND BASED ON SCAN LEVEL
    # --------------------------------------------------
    def build_command(self, target, output_file):

        if platform.system() == "Windows":
            base_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        else:
            base_path = shutil.which("nmap") or "nmap"

        if self.scan_level == 1:
            return [base_path, "-sT", "--top-ports", "100", target, "-oX", output_file]

        elif self.scan_level == 2:
            return [base_path, "-sS", "-sV", "-O", "--top-ports", "1000", target, "-oX", output_file]

        elif self.scan_level == 3:
            return [base_path, "-sS", "-sV", "-O", "-sU", "-p-", "--script", "vuln", "-T4", target, "-oX", output_file]

        elif self.scan_level == 4:
            return [base_path, "-sT", "--top-ports", "1000", target, "-oX", output_file]


    # --------------------------------------------------
    # PARSE NMAP XML OUTPUT
    # --------------------------------------------------
    def parse_xml(self, file):

        results = self.empty_result()

        try:
            tree = ET.parse(file)
            root = tree.getroot()
        except:
            return results

        for port in root.iter("port"):

            state = port.find("state")

            if state is not None and state.attrib.get("state") == "open":

                port_id = int(port.attrib["portid"])

                if port_id not in results["open_ports"]:
                    results["open_ports"].append(port_id)

                # Risk scoring logic
                if port_id in [80, 443]:
                    results["risk_score"] += 0.5
                elif port_id in [22, 21, 3306, 3389]:
                    results["risk_score"] += 3
                else:
                    results["risk_score"] += 1.5

                service = port.find("service")

                if service is not None:

                    product = service.attrib.get("product", "")
                    version = service.attrib.get("version", "")

                    tech = f"{product} {version}".strip()

                    if tech and tech not in results["technologies"]:
                        results["technologies"].append(tech)

        osmatch = root.find(".//osmatch")

        if osmatch is not None:
            results["os_detection"] = osmatch.attrib.get("name")

        return results