class DecisionEngine:

    def decide(self, results):

        ports = results.get("open_ports", [])
        tech = str(results.get("technologies", [])).lower()
        urls = results.get("katana_urls", [])

        decisions = {
            "run_fuzzing": False,
            "run_nikto": False,
            "run_dalfox": False,
            "run_sqlmap": False,
            "run_nuclei": True,
            "priority": "low"
        }

        # -------------------------
        # WEB DETECTION
        # -------------------------
        if 80 in ports or 443 in ports:
            decisions["run_fuzzing"] = True
            decisions["run_nikto"] = True

        # -------------------------
        # XSS / Injection detection
        # -------------------------
        if "php" in tech or "apache" in tech or "nginx" in tech:
            decisions["run_dalfox"] = True

        # -------------------------
        # SQL Injection detection
        # -------------------------
        if any("?" in url for url in urls):
            decisions["run_sqlmap"] = True

        # -------------------------
        # PRIORITY
        # -------------------------
        if len(ports) > 5:
            decisions["priority"] = "high"
        elif ports:
            decisions["priority"] = "medium"

        return decisions