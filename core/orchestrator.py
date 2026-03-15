import asyncio
import json
from datetime import datetime

# Recon
from module.recon.nmap_engine import NmapEngine
from module.tools.masscan_engine import MasscanEngine

# Crawlers
from module.crawling.katana_engine import KatanaEngine
from module.crawling.amass_engine import AmassEngine
from module.crawling.assetfinder_engine import AssetfinderEngine

# Web tools
from module.tools.whatweb_engine import WhatWebEngine
from module.tools.ffuf_engine import FfufEngine
from module.tools.nuclei_engine import NucleiEngine
from module.tools.harvester_engine import HarvesterEngine
from module.tools.gowitness_engine import GoWitnessEngine

# Vuln scanners
from module.vulnscan.nikto_engine import NiktoEngine
from module.vulnscan.dalfox_engine import DalfoxEngine
from module.vulnscan.sqlmap_engine import SqlmapEngine

# Intelligence
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

# Attack reasoning
from module.attack.attack_chain_builder import AttackChainBuilder
from module.attack.post_exploit_simulator import PostExploitSimulator
from core.attack_graph import AttackGraph

# Visualization
from core.graph_visualizer import GraphVisualizer

# Reporting
from core.report_generator import ReportGenerator


class Orchestrator:

    def __init__(self, scan_level=1):
        self.scan_level = scan_level
        self.SHODAN_API_KEY = "YOUR_SHODAN_KEY"

    def sanitize(self, obj):
        """Make results JSON safe"""
        if isinstance(obj, dict):
            return {k: self.sanitize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.sanitize(v) for v in obj]
        elif isinstance(obj, Exception):
            return str(obj)
        else:
            return obj

    async def run(self, target):

        print(f"\n[+] Starting ARCHAI scan for: {target}\n")

        results = {}

        # =================================================
        # PHASE 1 — MASSCAN
        # =================================================

        print("[+] Phase 1 → Fast port discovery (Masscan)")

        masscan = MasscanEngine()
        ports = await masscan.run(target)

        results["masscan_ports"] = ports

        # =================================================
        # PHASE 2 — NMAP
        # =================================================

        print("[+] Phase 2 → Detailed service scan (Nmap)")

        nmap = NmapEngine()

        if ports:
            nmap_results = await nmap.execute_ports(target, ports)
        else:
            nmap_results = await nmap.execute(target)

        results.update(nmap_results)

        # =================================================
        # PHASE 3 — RECON TOOLS
        # =================================================

        print("[+] Phase 3 → Running recon tools")

        tool_tasks = [
            WhatWebEngine().run(target),
            FfufEngine().run(target),
            NucleiEngine().run(target),
            HarvesterEngine().run(target),
            GoWitnessEngine().run(target)
        ]

        tool_results = await asyncio.gather(*tool_tasks, return_exceptions=True)

        results["whatweb"] = tool_results[0]
        results["ffuf"] = tool_results[1]
        results["nuclei"] = tool_results[2]
        results["harvester"] = tool_results[3]
        results["gowitness"] = tool_results[4]

        # =================================================
        # PHASE 4 — CRAWLING
        # =================================================

        print("[+] Phase 4 → Crawling & subdomain discovery")

        crawl_tasks = [
            KatanaEngine().run(target),
            AssetfinderEngine().run(target),
        ]

        crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)

        results["katana_urls"] = crawl_results[0]
        results["assetfinder_subdomains"] = crawl_results[1]

        # =================================================
        # PHASE 5 — VULNERABILITY SCANNERS
        # =================================================

        print("[+] Phase 5 → Vulnerability scanners")

        vuln_tasks = [
            NiktoEngine().run(target),
            DalfoxEngine().run(target),
        ]

        vuln_results = await asyncio.gather(*vuln_tasks, return_exceptions=True)

        results["nikto"] = vuln_results[0]
        results["dalfox"] = vuln_results[1]

        # =================================================
        # INFRASTRUCTURE
        # =================================================

        asn = ASNLookup()
        infra = asn.lookup(target)

        results["infrastructure"] = infra

        classifier = InfrastructureClassifier()
        results["infrastructure_type"] = classifier.classify(infra.get("asn"))

        # =================================================
        # NVD LOOKUP
        # =================================================

        nvd = NVDEngine()
        nvd_cves = []

        for tech in results.get("technologies", []):
            nvd_cves.extend(nvd.search(tech))

        results["nvd_cves"] = nvd_cves

        # =================================================
        # ANOMALIES
        # =================================================

        anomaly_engine = AnomalyEngine()
        anomalies = anomaly_engine.detect(results)

        results["anomalies"] = anomalies

        # =================================================
        # RISK SCORE
        # =================================================

        risk_engine = RiskScoring()

        final_risk = risk_engine.calculate(
            results.get("risk_score", 0),
            "pipeline",
            nvd_cves,
            len(anomalies)
        )

        results["final_risk_score"] = min(round(final_risk, 2), 10)

        # =================================================
        # EXPOSURE
        # =================================================

        exposure = ExposureClassifier()
        results["exposure_level"] = exposure.classify(results["final_risk_score"])

        # =================================================
        # CONFIDENCE
        # =================================================

        confidence_engine = ConfidenceEngine()
        results["confidence_score"] = confidence_engine.calculate(results)

        # =================================================
        # ATTACK REASONING
        # =================================================

        reasoner = VulnerabilityReasoner()
        results["vulnerability_analysis"] = reasoner.analyze(results)

        chain_builder = AttackChainBuilder()
        attack_paths = chain_builder.generate(results)

        results["attack_paths"] = attack_paths

        simulator = PostExploitSimulator()
        results["post_exploitation"] = simulator.simulate(results)

        graph = AttackGraph()
        results["attack_graph"] = graph.generate(results)

        # =================================================
        # GRAPH VISUALIZATION
        # =================================================

        visualizer = GraphVisualizer()
        graph_file = visualizer.generate(target, attack_paths)

        results["attack_graph_visualization"] = graph_file

        # =================================================
        # EXPLOITS
        # =================================================

        exploit_mapper = ExploitMapper()
        results["exploit_suggestions"] = exploit_mapper.suggest(results)

        # =================================================
        # REPORT
        # =================================================

        report_generator = ReportGenerator()
        results["pentest_report"] = report_generator.generate(target, results)

        # =================================================
        # EXPORT JSON
        # =================================================

        filename = f"archai_report_{target.replace('.', '_')}.json"

        report_data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "results": self.sanitize(results)
        }

        with open(filename, "w") as f:
            json.dump(report_data, f, indent=4)

        results["report_file"] = filename

        print("\n[+] ARCHAI Intelligence Processing Complete\n")

        return results