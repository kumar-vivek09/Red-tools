class AdaptiveEngine:

    def adapt(self, results):

        actions = []

        ports = results.get("open_ports", [])
        anomalies = results.get("anomalies", [])

        # -------------------------
        # High risk detected
        # -------------------------
        if len(ports) > 3:
            actions.append("Increase scan depth")

        # -------------------------
        # Suspicious ports
        # -------------------------
        if 31337 in ports:
            actions.append("Investigate backdoor port")

        # -------------------------
        # anomalies
        # -------------------------
        if anomalies:
            actions.append("Run deeper vulnerability scan")

        if not actions:
            actions.append("No adaptation needed")

        return actions