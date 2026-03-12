class AttackGraph:

    def generate(self, results):

        attack_paths = []

        open_ports = results.get("open_ports", [])
        technologies = results.get("technologies", [])

        # SMB attack path
        if 445 in open_ports:
            attack_paths.append(
                "SMB detected → Possible EternalBlue exploitation → Lateral movement"
            )

        # SSH attack path
        if 22 in open_ports:
            attack_paths.append(
                "SSH service detected → Credential brute-force → Privilege escalation"
            )

        # Web attack path
        if 80 in open_ports or 443 in open_ports:

            attack_paths.append(
                "Web server detected → Directory enumeration → Web vulnerability scanning"
            )

            attack_paths.append(
                "Web application → Authentication bypass → Sensitive data exposure"
            )

        # Database exposure
        if 3306 in open_ports:
            attack_paths.append(
                "MySQL exposed → Weak credentials → Database compromise"
            )

        return attack_paths