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
# NEW TOOL IMPORTS
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
        self.SHODAN_API_KEY = "r48wSWX5zJSgpqBVURSC8QVPCmKn9Qrd"

    async def run(self, target):

        print(f"\n[+] Starting ARCHAI scan for: {target}")
        print(f"[+] Scan Level: {self.scan_level}\n")

        escalation_path = ["light"]

        # -------------------
        # PHASE 1 — LIGHT
        # -------------------
        engine = NmapEngine(scan_level=1)
        results = await engine.execute(target)

        # -------------------
        # EXTERNAL TOOL PIPELINE
        # -------------------
        print("\n[+] Running integrated recon tools\n")

        try:
            masscan = MasscanEngine().run(target)
            results["masscan"] = masscan
        except Exception:
            results["masscan"] = None

        try:
            whatweb = WhatWebEngine().run(target)
            results["whatweb"] = whatweb
        except Exception:
            results["whatweb"] = None

        try:
            ffuf = FfufEngine().run(target)
            results["ffuf"] = ffuf
        except Exception:
            results["ffuf"] = None

        try:
            nuclei = NucleiEngine().run(target)
            results["nuclei"] = nuclei
        except Exception:
            results["nuclei"] = None

        try:
            harvester = HarvesterEngine().run(target)
            results["harvester"] = harvester
        except Exception:
            results["harvester"] = None

        try:
            gowitness = GoWitnessEngine().run(target)
            results["gowitness"] = gowitness
        except Exception:
            results["gowitness"] = None

        # -------------------
        # Infrastructure
        # -------------------
        asn = ASNLookup()
        infra = asn.lookup(target)
        results["infrastructure"] = infra

        classifier = InfrastructureClassifier()
        infra_type = classifier.classify(infra.get("asn"))
        results["infrastructure_type"] = infra_type

        # -------------------
        # ADAPTIVE LOGIC
        # -------------------
        if self.scan_level == 4:

            open_ports = results.get("open_ports", [])
            base_risk = results.get("risk_score", 0)

            high_risk_ports = {21, 22, 3306, 3389}
            uncommon_ports = [p for p in open_ports if p > 1024 and p not in {8080, 8443}]

            # Step 2 → Balanced escalation
            if high_risk_ports.intersection(open_ports) or uncommon_ports:
                print("[Adaptive] Risky service detected → Balanced escalation.")
                balanced = NmapEngine(scan_level=2)
                results = await balanced.execute(target)
                escalation_path.append("balanced")

            # Step 3 → If vulnerability found → Aggressive deep scan
            if results.get("nse_vulnerabilities"):
                print("[Adaptive] Vulnerability detected → FULL Aggressive escalation.")
                aggressive = NmapEngine(scan_level=3)
                results = await aggressive.execute(target)
                escalation_path.append("aggressive")

        # -------------------
        # SHODAN
        # -------------------
        shodan_ports = []
        shodan_cves = []

        if infra.get("ip") and self.SHODAN_API_KEY != "YOUR_REAL_SHODAN_KEY":
            shodan = ShodanEngine(self.SHODAN_API_KEY)
            shodan_data = shodan.lookup(infra.get("ip"))
            shodan_ports = shodan_data.get("ports", [])
            shodan_cves = [{"cve_id": c, "cvss": 5} for c in shodan_data.get("vulns", [])]

        results["shodan_ports"] = shodan_ports

        if shodan_ports:
            nmap_ports = set(results.get("open_ports", []))
            results["port_mismatch"] = list(set(shodan_ports).symmetric_difference(nmap_ports))
        else:
            results["port_mismatch"] = []

        # -------------------
        # NVD LIVE
        # -------------------
        nvd = NVDEngine()
        nvd_cves = []

        for tech in results.get("technologies", []):
            nvd_cves.extend(nvd.search(tech))

        results["nvd_cves"] = nvd_cves

        # -------------------
        # ANOMALIES
        # -------------------
        anomaly_engine = AnomalyEngine()
        anomalies = anomaly_engine.detect(results)
        results["anomalies"] = anomalies

        # -------------------
        # RISK SCORING
        # -------------------
        nse_vulns = results.get("nse_vulnerabilities", [])
        total_cves = shodan_cves + nvd_cves

        risk_engine = RiskScoring()
        final_risk = risk_engine.calculate(
            results.get("risk_score", 0),
            escalation_path[-1],
            total_cves,
            len(anomalies)
        )

        final_risk += min(len(nse_vulns) * 2, 4)

        results["final_risk_score"] = min(round(final_risk, 2), 10)

        # -------------------
        # EXPOSURE LEVEL
        # -------------------
        exposure = ExposureClassifier()
        results["exposure_level"] = exposure.classify(results["final_risk_score"])

        # -------------------
        # CONFIDENCE
        # -------------------
        confidence_engine = ConfidenceEngine()
        results["confidence_score"] = confidence_engine.calculate(results)

        results["escalation_path"] = " → ".join(escalation_path)

        # -------------------
        # VULNERABILITY REASONING
        # -------------------
        reasoner = VulnerabilityReasoner()
        results["vulnerability_analysis"] = reasoner.analyze(results)

        # -------------------
        # ATTACK PATH PLANNING
        # -------------------
        attack_graph = AttackGraph()
        results["attack_paths"] = attack_graph.generate(results)

        # -------------------
        # EXPLOIT SUGGESTIONS
        # -------------------
        exploit_mapper = ExploitMapper()
        results["exploit_suggestions"] = exploit_mapper.suggest(results)

        # -------------------
        # PENTEST REPORT
        # -------------------
        report_generator = ReportGenerator()
        results["pentest_report"] = report_generator.generate(target, results)

        # -------------------
        # JSON EXPORT
        # -------------------
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