class AttackSimulator:

    def simulate(self, results):

        paths = []

        ports = results.get("open_ports", [])
        tech = str(results.get("technologies", [])).lower()
        cves = results.get("nvd_cves", [])

        # ---------------------------
        # WEB ATTACK PATH
        # ---------------------------
        if 80 in ports or 443 in ports:
            paths.append(
                "Attacker finds web server → performs directory brute-force → finds hidden endpoints → exploits vulnerability → gains shell"
            )

        # ---------------------------
        # SSH ATTACK PATH
        # ---------------------------
        if 22 in ports:
            paths.append(
                "Attacker detects SSH → brute-force login → gains credentials → escalates privileges"
            )

        # ---------------------------
        # CVE BASED ATTACK
        # ---------------------------
        if cves:
            paths.append(
                "Attacker identifies vulnerable software → maps CVE → uses exploit → gains remote access"
            )

        # ---------------------------
        # DATABASE ATTACK
        # ---------------------------
        if 3306 in ports:
            paths.append(
                "Database exposed → attacker connects → dumps data → extracts sensitive info"
            )

        # ---------------------------
        # BACKDOOR PORT
        # ---------------------------
        if 31337 in ports:
            paths.append(
                "Suspicious high port detected → possible backdoor → attacker probes → gains hidden access"
            )

        if not paths:
            paths.append("No strong attack path identified")

        return paths