# module/intelligence/false_positive_filter.py


class FalsePositiveFilter:

    ENTERPRISE_DOMAINS = [
        "google.com",
        "microsoft.com",
        "amazon.com",
        "cloudflare.com",
        "apple.com",
        "facebook.com"
    ]

    ENTERPRISE_SERVER_KEYWORDS = [
        "gws",
        "cloudflare",
        "akamai",
        "fastly"
    ]

    def is_enterprise_domain(self, target):
        return any(domain in target for domain in self.ENTERPRISE_DOMAINS)

    def is_enterprise_server(self, technologies):
        for tech in technologies:
            for keyword in self.ENTERPRISE_SERVER_KEYWORDS:
                if keyword.lower() in tech.lower():
                    return True
        return False

    def adjust(self, target, results):

        technologies = results.get("technologies", [])
        open_ports = results.get("open_ports", [])

        enterprise_domain = self.is_enterprise_domain(target)
        enterprise_server = self.is_enterprise_server(technologies)

        # Remove unrealistic OSINT enrichment for enterprise targets
        if enterprise_domain or enterprise_server:

            # Remove simulated OSINT data
            results["exposed_services"] = []
            results["historical_ports"] = []
            results["leaked_banners"] = []

            # Remove CVE findings (very unlikely for major enterprise infra)
            results["cve_findings"] = []

            # Remove FTP if detected (likely false positive)
            if 21 in open_ports:
                open_ports.remove(21)

            results["open_ports"] = open_ports

            # Recalculate more realistic risk
            realistic_score = len(open_ports) * 1.2

            results["final_risk_score"] = min(realistic_score, 3)

        return results