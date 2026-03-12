class AnomalyDetector:

    def detect(self, scan_data):

        anomalies = []

        if 21 in scan_data.get("open_ports", []):
            anomalies.append("Unexpected FTP port exposed")

        if len(scan_data.get("subdomains", [])) > 20:
            anomalies.append("High subdomain footprint")

        if scan_data.get("risk_score", 0) > 8:
            anomalies.append("Abnormally high systemic risk")

        return anomalies