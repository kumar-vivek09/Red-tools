import json
from datetime import datetime


class ReportGenerator:

    def generate(self, target, results):

        report = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "risk_score": results.get("final_risk_score"),
                "exposure_level": results.get("exposure_level"),
                "confidence": results.get("confidence_score")
            },
            "open_ports": results.get("open_ports"),
            "technologies": results.get("technologies"),
            "vulnerabilities": results.get("vulnerability_analysis"),
            "attack_paths": results.get("attack_paths"),
            "exploit_suggestions": results.get("exploit_suggestions")
        }

        filename = f"archai_pentest_report_{target.replace('.', '_')}.json"

        with open(filename, "w") as f:
            json.dump(report, f, indent=4)

        return filename