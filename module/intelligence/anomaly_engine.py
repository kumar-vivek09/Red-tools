class AnomalyEngine:

    def detect(self, results):

        anomalies = []

        open_ports = results.get("open_ports", [])
        infra_type = results.get("infrastructure_type")

        # Uncommon high ports
        for port in open_ports:
            if port > 10000:
                anomalies.append(f"Unusual high port detected: {port}")

        # SSH exposed on cloud/CDN
        if 22 in open_ports and infra_type in ["cloud", "cdn"]:
            anomalies.append("Public SSH exposed on cloud/CDN infrastructure")

        # Too many open ports
        if len(open_ports) > 8:
            anomalies.append("Large attack surface detected")

        return anomalies