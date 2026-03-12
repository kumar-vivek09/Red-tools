class ConfidenceEngine:

    def calculate(self, results):

        confidence = 0.5

        confidence += min(len(results.get("open_ports", [])) * 0.05, 0.2)

        if results.get("os_detection"):
            confidence += 0.1

        if results.get("technologies"):
            confidence += 0.1

        return round(min(confidence, 1.0), 2)