class RiskScoring:

    def calculate(self, base_score, escalation_level, cve_list, anomaly_count):

        risk = base_score * 0.6

        # Escalation weight
        if escalation_level == "balanced":
            risk += 1.5
        elif escalation_level == "aggressive":
            risk += 3

        # CVE weighting based on severity
        for cve in cve_list:
            cvss = cve.get("cvss", 0)

            if cvss >= 9:
                risk += 1.5
            elif cvss >= 7:
                risk += 1.0
            elif cvss >= 4:
                risk += 0.5

        # Cap CVE influence
        risk = min(risk, 10)

        # Anomaly weight
        risk += min(anomaly_count * 0.5, 2)

        return min(round(risk, 2), 10)