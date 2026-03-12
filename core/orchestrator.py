import asyncio
import json
from datetime import datetime

from module.recon.nmap_engine import NmapEngine
from module.intelligence.risk_scoring import RiskScoring
from module.intelligence.confidence_engine import ConfidenceEngine
from module.intelligence.asn_lookup import ASNLookup
from module.intelligence.infrastructure_classifier import InfrastructureClassifier
from module.intelligence.shodan_engine import ShodanEngine
from module.intelligence.nvd_engine import NVDEngine
from module.intelligence.anomaly_engine import AnomalyEngine
from module.intelligence.exposure_classifier import ExposureClassifier
from module.intelligence.vulnerability_reasoner import VulnerabilityReasoner
from module.intelligence.exploit_mapper import ExploitMapper

from core.attack_graph import AttackGraph
from core.report_generator import ReportGenerator

# -------------------
# TOOL IMPORTS
# -------------------
from module.tools.masscan_engine import MasscanEngine
from module.tools.whatweb_engine import WhatWebEngine
from module.tools.ffuf_engine import FfufEngine
from module.tools.nuclei_engine import NucleiEngine
from module.tools.harvester_engine import HarvesterEngine
from module.tools.gowitness_engine import GoWitnessEngine


class Orchestrator:

    def __init__(self, scan_level=1):
        self.scan_level = scan_level
        self.SHODAN_API_KEY = "YOUR_SHODAN_KEY"

    async def run(self, target):

        print(f"\n[+] Starting ARCHAI scan for: {target}")
        print(f"[+] Scan Level: {self.scan_level}\n")

        escalation_path = []

        # =================================================
        # PHASE 1 — FAST DISCOVERY (LIGHT SCAN)
        # =================================================

        print("[+] Phase 1 → Initial reconnaissance scan")

        nmap_light = NmapEngine(scan_level=1)
        results = await nmap_light.execute(target)

        escalation_path.append("light")

        open_ports = results.get("open_ports", [])

        # =================================================
        # PHASE 2 — BALANCED ESCALATION
        # =================================================

        high_risk_ports = {21, 22, 3306, 3389}
        suspicious_ports = high_risk_ports.intersection(open_ports)

        if suspicious_ports or len(open_ports) > 5:

            print("[Adaptive] Suspicious services detected → Balanced scan")

            nmap_balanced = NmapEngine(scan_level=2)
            results_balanced = await nmap_balanced.execute(target)

            results.update(results_balanced)
            escalation_path.append("balanced")

        # =================================================
        # PHASE 3 — AGGRESSIVE SCAN (ONLY IF NEEDED)
        # =================================================

        if results.get("risk_score", 0) > 4:

            print("[Adaptive] High risk detected → Aggressive scan")

            nmap_aggressive = NmapEngine(scan_level=3)
            results_aggressive = await nmap_aggressive.execute(target)

            results.update(results_aggressive)
            escalation_path.append("aggressive")

        # =================================================
        # PHASE 4 — UDP SCAN (SMART TRIGGER)
        # =================================================

        if 53 in open_ports or 161 in open_ports:

            print("[Adaptive] UDP services suspected → Running UDP scan")

            nmap_udp = NmapEngine(scan_level=4)
            results_udp = await nmap_udp.execute(target)

            results.update(results_udp)
            escalation_path.append("udp")

        # =================================================
        # PHASE 5 — PARALLEL TOOL EXECUTION
        # =================================================

        print("\n[+] Running integrated recon tools in parallel\n")

        masscan_engine = MasscanEngine()
        whatweb_engine = WhatWebEngine()
        ffuf_engine = FfufEngine()
        nuclei_engine = NucleiEngine()
        harvester_engine = HarvesterEngine()
        gowitness_engine = GoWitnessEngine()

        tool_results = await asyncio.gather(
            masscan_engine.run(target),
            whatweb_engine.run(target),
            ffuf_engine.run(target),
            nuclei_engine.run(target),
            harvester_engine.run(target),
            gowitness_engine.run(target),
            return_exceptions=True
        )

        results["masscan"] = tool_results[0]
        results["whatweb"] = tool_results[1]
        results["ffuf"] = tool_results[2]
        results["nuclei"] = tool_results[3]
        results["harvester"] = tool_results[4]
        results["gowitness"] = tool_results[5]

        # =================================================
        # INFRASTRUCTURE ANALYSIS
        # =================================================

        asn = ASNLookup()
        infra = asn.lookup(target)

        results["infrastructure"] = infra

        classifier = InfrastructureClassifier()
        results["infrastructure_type"] = classifier.classify(infra.get("asn"))

        # =================================================
        # SHODAN INTELLIGENCE
        # =================================================

        shodan_ports = []
        shodan_cves = []

        if infra.get("ip") and self.SHODAN_API_KEY != "YOUR_SHODAN_KEY":

            shodan = ShodanEngine(self.SHODAN_API_KEY)
            shodan_data = shodan.lookup(infra.get("ip"))

            shodan_ports = shodan_data.get("ports", [])

            shodan_cves = [
                {"cve_id": cve, "cvss": 5}
                for cve in shodan_data.get("vulns", [])
            ]

        results["shodan_ports"] = shodan_ports

        if shodan_ports:
            nmap_ports = set(results.get("open_ports", []))
            results["port_mismatch"] = list(
                set(shodan_ports).symmetric_difference(nmap_ports)
            )
        else:
            results["port_mismatch"] = []

        # =================================================
        # NVD VULNERABILITY LOOKUP
        # =================================================

        nvd = NVDEngine()
        nvd_cves = []

        for tech in results.get("technologies", []):
            nvd_cves.extend(nvd.search(tech))

        results["nvd_cves"] = nvd_cves

        # =================================================
        # ANOMALY DETECTION
        # =================================================

        anomaly_engine = AnomalyEngine()
        anomalies = anomaly_engine.detect(results)

        results["anomalies"] = anomalies

        # =================================================
        # RISK SCORING
        # =================================================

        total_cves = shodan_cves + nvd_cves

        risk_engine = RiskScoring()

        final_risk = risk_engine.calculate(
            results.get("risk_score", 0),
            escalation_path[-1],
            total_cves,
            len(anomalies)
        )

        results["final_risk_score"] = min(round(final_risk, 2), 10)

        # =================================================
        # EXPOSURE CLASSIFICATION
        # =================================================

        exposure = ExposureClassifier()
        results["exposure_level"] = exposure.classify(
            results["final_risk_score"]
        )

        # =================================================
        # CONFIDENCE ENGINE
        # =================================================

        confidence_engine = ConfidenceEngine()
        results["confidence_score"] = confidence_engine.calculate(results)

        results["escalation_path"] = " → ".join(escalation_path)

        # =================================================
        # VULNERABILITY REASONING
        # =================================================

        reasoner = VulnerabilityReasoner()
        results["vulnerability_analysis"] = reasoner.analyze(results)

        # =================================================
        # ATTACK PATH GENERATION
        # =================================================

        attack_graph = AttackGraph()
        results["attack_paths"] = attack_graph.generate(results)

        # =================================================
        # EXPLOIT SUGGESTIONS
        # =================================================

        exploit_mapper = ExploitMapper()
        results["exploit_suggestions"] = exploit_mapper.suggest(results)

        # =================================================
        # REPORT GENERATION
        # =================================================

        report_generator = ReportGenerator()
        results["pentest_report"] = report_generator.generate(target, results)

        # =================================================
        # JSON EXPORT
        # =================================================

        filename = f"archai_report_{target.replace('.', '_')}.json"

        report_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }

        with open(filename, "w") as f:
            json.dump(report_data, f, indent=4)

        results["report_file"] = filename

        print("\n[+] ARCHAI Intelligence Processing Complete\n")

        return results