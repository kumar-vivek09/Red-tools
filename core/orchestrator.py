import asyncio
import json
from datetime import datetime

from module.recon.nmap_engine import NmapEngine
from module.tools.masscan_engine import MasscanEngine

from module.crawling.katana_engine import KatanaEngine
from module.crawling.assetfinder_engine import AssetfinderEngine

from module.tools.whatweb_engine import WhatWebEngine
from module.tools.ffuf_engine import FfufEngine
from module.tools.nuclei_engine import NucleiEngine
from module.tools.harvester_engine import HarvesterEngine
from module.tools.gowitness_engine import GoWitnessEngine

from module.vulnscan.nikto_engine import NiktoEngine
from module.vulnscan.dalfox_engine import DalfoxEngine

from module.intelligence.risk_scoring import RiskScoring
from module.intelligence.confidence_engine import ConfidenceEngine
from module.intelligence.asn_lookup import ASNLookup
from module.intelligence.infrastructure_classifier import InfrastructureClassifier
from module.intelligence.nvd_engine import NVDEngine
from module.intelligence.anomaly_engine import AnomalyEngine
from module.intelligence.exposure_classifier import ExposureClassifier
from module.intelligence.vulnerability_reasoner import VulnerabilityReasoner
from module.intelligence.exploit_mapper import ExploitMapper

from module.attack.attack_chain_builder import AttackChainBuilder
from module.attack.post_exploit_simulator import PostExploitSimulator

from core.attack_graph import AttackGraph
from core.graph_visualizer import GraphVisualizer
from core.report_generator import ReportGenerator


class Orchestrator:


    def __init__(self, scan_level=1):
        self.scan_level = scan_level
        self.SHODAN_API_KEY = "r48wSWX5zJSgpqBVURSC8QVPCmKn9Qrd"

    def sanitize(self, obj):
        if isinstance(obj, dict):
            return {k: self.sanitize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.sanitize(v) for v in obj]
        if isinstance(obj, Exception):
            return str(obj)
        return obj


    async def safe_run(self, coro, timeout=120):
        try:
            return await asyncio.wait_for(coro, timeout)
        except Exception as e:
            return str(e)


    async def run(self, target):

        print(f"\n[+] Starting ARCHAI scan for: {target}\n")

        results = {}

        # ===============================
        # Phase 1 – Masscan
        # ===============================

        print("[+] Phase 1 → Fast port discovery (Masscan)")

        masscan = MasscanEngine()

        ports = await masscan.run(target)  # ❗ direct await

        print(f"[DEBUG] Ports from masscan: {ports}")

        results["masscan_ports"] = ports

        # ===============================
        # Phase 2 – Nmap
        # ===============================

        print("[+] Phase 2 → Detailed service scan (Nmap)")

        nmap = NmapEngine(self.scan_level)

        if ports:
            print("[DEBUG] Running Nmap on discovered ports")
            nmap_results = await nmap.execute_ports(target, ports)
        else:
            print("[DEBUG] Masscan empty → running full Nmap")
            nmap_results = await nmap.execute(target)

        print("[DEBUG] Nmap completed")

        results.update(nmap_results)

        print(f"[DEBUG] Open ports: {results.get('open_ports')}")



        # ===============================
        # Phase 3 – Recon + Crawling
        # ===============================

        print("[+] Phase 3 → Recon + crawling pipeline")

        recon_tasks = [

            self.safe_run(WhatWebEngine().run(target)),
            self.safe_run(FfufEngine().run(target)),
            self.safe_run(NucleiEngine().run(target)),
            self.safe_run(HarvesterEngine().run(target)),
            self.safe_run(GoWitnessEngine().run(target)),

            self.safe_run(KatanaEngine().run(target)),
            self.safe_run(AssetfinderEngine().run(target))

        ]

        recon_results = await asyncio.gather(*recon_tasks)

        results["whatweb"] = recon_results[0]
        results["ffuf"] = recon_results[1]
        results["nuclei"] = recon_results[2]
        results["harvester"] = recon_results[3]
        results["gowitness"] = recon_results[4]
        results["katana_urls"] = recon_results[5]
        results["assetfinder_subdomains"] = recon_results[6]


        # ===============================
        # Phase 4 – Vulnerability scan
        # ===============================

        print("[+] Phase 4 → Vulnerability scanners")

        vuln_tasks = [

            self.safe_run(NiktoEngine().run(target)),
            self.safe_run(DalfoxEngine().run(target))

        ]

        vuln_results = await asyncio.gather(*vuln_tasks)

        results["nikto"] = vuln_results[0]
        results["dalfox"] = vuln_results[1]


        # ===============================
        # Intelligence
        # ===============================

        asn = ASNLookup()
        infra = asn.lookup(target)

        results["infrastructure"] = infra

        classifier = InfrastructureClassifier()
        results["infrastructure_type"] = classifier.classify(infra.get("asn"))


        nvd = NVDEngine()

        nvd_cves = []

        for tech in results.get("technologies", []):

            nvd_cves.extend(nvd.search(tech))

        results["nvd_cves"] = nvd_cves


        anomaly_engine = AnomalyEngine()

        anomalies = anomaly_engine.detect(results)

        results["anomalies"] = anomalies


        risk_engine = RiskScoring()

        final_risk = risk_engine.calculate(

            results.get("risk_score", 0),
            "pipeline",
            nvd_cves,
            len(anomalies)

        )

        results["final_risk_score"] = min(round(final_risk, 2), 10)


        exposure = ExposureClassifier()

        results["exposure_level"] = exposure.classify(results["final_risk_score"])


        confidence_engine = ConfidenceEngine()

        results["confidence_score"] = confidence_engine.calculate(results)


        reasoner = VulnerabilityReasoner()

        results["vulnerability_analysis"] = reasoner.analyze(results)


        chain_builder = AttackChainBuilder()

        attack_paths = chain_builder.generate(results)

        results["attack_paths"] = attack_paths


        simulator = PostExploitSimulator()

        results["post_exploitation"] = simulator.simulate(results)


        graph = AttackGraph()

        results["attack_graph"] = graph.generate(results)


        visualizer = GraphVisualizer()

        graph_file = visualizer.generate(target, attack_paths)

        results["attack_graph_visualization"] = graph_file


        exploit_mapper = ExploitMapper()

        results["exploit_suggestions"] = exploit_mapper.suggest(results)


        report_generator = ReportGenerator()

        results["pentest_report"] = report_generator.generate(target, results)


        filename = f"archai_report_{target.replace('.', '_')}.json"


        report_data = {

            "target": target,
            "timestamp": datetime.now().isoformat(),
            "results": self.sanitize(results)

        }


        with open(filename, "w") as f:

            json.dump(report_data, f, indent=4)


        results["report_file"] = filename


        print("\n[+] ARCHAI scan completed successfully\n")

        return results