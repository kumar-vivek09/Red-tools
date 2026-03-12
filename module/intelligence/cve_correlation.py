class CVECorrelationEngine:

    LOCAL_CVE_DB = {
        "Apache 2.4.49": {
            "cve": "CVE-2021-41773",
            "severity": 9.8
        }
    }

    def correlate(self, tech_stack):
        findings = []

        for tech in tech_stack:
            if tech in self.LOCAL_CVE_DB:
                findings.append({
                    "technology": tech,
                    "cve": self.LOCAL_CVE_DB[tech]["cve"],
                    "severity": self.LOCAL_CVE_DB[tech]["severity"]
                })

        return findings