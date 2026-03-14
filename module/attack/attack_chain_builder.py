class AttackChainBuilder:

    def generate(self, results):

        chains = []

        ports = results.get("open_ports", [])
        tech = results.get("technologies", [])

        # Web attack chain
        if 80 in ports or 443 in ports:

            chains.append(
                "Recon → Web server discovered → Directory enumeration → "
                "Vulnerability discovery → Possible web shell access"
            )

        # SSH attack chain
        if 22 in ports:

            chains.append(
                "Recon → SSH service detected → Credential attack surface → "
                "Possible unauthorized access"
            )

        # CVE based chain
        if results.get("nvd_cves"):

            chains.append(
                "Recon → Software version identified → CVE discovered → "
                "Potential exploitation path"
            )

        return chains