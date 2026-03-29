import asyncio
import json
from datetime import datetime

# Recon
from module.recon.nmap_engine import NmapEngine
from module.tools.masscan_engine import MasscanEngine

# Crawling
from module.crawling.katana_engine import KatanaEngine
from module.crawling.assetfinder_engine import AssetfinderEngine

# Tools
from module.tools.whatweb_engine import WhatWebEngine
from module.tools.hybrid_fuzzer import HybridFuzzer
from module.tools.nuclei_engine import NucleiEngine
from module.tools.harvester_engine import HarvesterEngine
from module.tools.gowitness_engine import GoWitnessEngine

# Vuln
from module.vulnscan.nikto_engine import NiktoEngine
from module.vulnscan.dalfox_engine import DalfoxEngine
from module.vulnscan.sqlmap_engine import SqlmapEngine

# Intelligence
from module.intelligence.risk_scoring import RiskScoring
from module.intelligence.confidence_engine import ConfidenceEngine
from module.intelligence.asn_lookup import ASNLookup
from module.intelligence.infrastructure_classifier import InfrastructureClassifier
from module.intelligence.nvd_engine import NVDEngine
from module.intelligence.anomaly_engine import AnomalyEngine
from module.intelligence.exposure_classifier import ExposureClassifier
from module.intelligence.vulnerability_reasoner import VulnerabilityReasoner
from module.intelligence.exploit_mapper import ExploitMapper

# Attack
from module.attack.attack_chain_builder import AttackChainBuilder
from module.attack.post_exploit_simulator import PostExploitSimulator
from module.attack.attack_simulator import AttackSimulator

# AI Engines
from core.decision_engine import DecisionEngine
from module.attack.exploit_engine import ExploitEngine
from module.attack.payload_engine import PayloadEngine
from module.attack.adaptive_engine import AdaptiveEngine

# Graph + Report
from core.attack_graph import AttackGraph
from core.graph_visualizer import GraphVisualizer
from core.report_generator import ReportGenerator
from core.ai_report_engine import AIReportEngine


class Orchestrator:

    def __init__(self, scan_level=1):
        self.scan_level = scan_level
        self.SHODAN_API_KEY = "YOUR_SHODAN_KEY"

    # -------------------------
    # SANITIZE JSON
    # -------------------------
    def sanitize(self, obj):
        if isinstance(obj, dict):
            return {k: self.sanitize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.sanitize(v) for v in obj]
        if isinstance(obj, Exception):
            return str(obj)
        return obj

    # -------------------------
    # SAFE RUN
    # -------------------------
    async def safe_run(self, coro, timeout=300):
        try:
            return await asyncio.wait_for(coro, timeout)
        except Exception as e:
            return str(e)

    # -------------------------
    # MAIN RUN
    # -------------------------
    async def run(self, target):

        print(f"\n[+] Starting ARCHAI scan for: {target}")
        print(f"[+] Scan Level: {self.scan_level}\n")

        results = {}

        # ==========================
        # PHASE 1 – MASSCAN
        # ==========================
        print("[+] Phase 1 → Fast port discovery (Masscan)")

        masscan = MasscanEngine()
        ports = await masscan.run(target)

        results["masscan_ports"] = ports
        print(f"[DEBUG] Ports from masscan: {ports}")

        # ==========================
        # PHASE 2 – NMAP
        # ==========================
        print("[+] Phase 2 → Detailed service scan (Nmap)")

        nmap = NmapEngine(self.scan_level)

        if ports:
            print("[DEBUG] Running targeted Nmap")
            nmap_results = await nmap.execute_ports(target, ports)
        else:
            print("[DEBUG] Masscan empty → running full Nmap")
            nmap_results = await nmap.execute(target)

        results.update(nmap_results)
        print(f"[DEBUG] Open ports: {results.get('open_ports')}")

        # ==========================
        # AI DECISION ENGINE
        # ==========================
        decision_engine = DecisionEngine()
        decisions = decision_engine.decide(results)

        print(f"[AI] Decisions: {decisions}")


        # ===============================
        # PHASE 3 – RECON + CRAWLING
        # ===============================

        # ============================
        # PHASE 3 → RECON
        # ============================

        print("[+] Phase 3 → Recon + crawling pipeline")

        recon_tasks = [
            self.safe_run(WhatWebEngine().run(target)),
            self.safe_run(NucleiEngine().run(target)),
            self.safe_run(HarvesterEngine().run(target)),
            self.safe_run(GoWitnessEngine().run(target)),
            self.safe_run(KatanaEngine().run(target)),
            self.safe_run(AssetfinderEngine().run(target))
        ]

        # ADD FUZZING ALWAYS (NO AI SKIP)
        print("[AI] Running Hybrid Fuzzer (Ferox + Dirsearch)")
        recon_tasks.append(self.safe_run(HybridFuzzer().run(target)))

        recon_results = await asyncio.gather(*recon_tasks)

        results["whatweb"] = recon_results[0]
        results["nuclei"] = recon_results[1]
        results["harvester"] = recon_results[2]
        results["gowitness"] = recon_results[3]
        results["katana_urls"] = recon_results[4]
        results["assetfinder_subdomains"] = recon_results[5]
        results["fuzzing"] = recon_results[6]


        # ==========================
        # PHASE 4 – VULNERABILITY
        # ==========================
        print("[+] Phase 4 → Vulnerability scanners")

        vuln_tasks = []

        if decisions["run_nikto"]:
            print("[AI] Running Nikto")
            vuln_tasks.append(self.safe_run(NiktoEngine().run(target)))

        if decisions["run_dalfox"]:
            print("[AI] Running Dalfox")
            vuln_tasks.append(self.safe_run(DalfoxEngine().run(target)))

        if decisions["run_sqlmap"]:
            print("[AI] Running SQLMap")
            vuln_tasks.append(self.safe_run(SqlmapEngine().run(target)))

        if vuln_tasks:
            vuln_results = await asyncio.gather(*vuln_tasks)
            results["vuln_results"] = vuln_results
        else:
            print("[AI] Skipping vulnerability scans")
            results["vuln_results"] = []

        # ==========================
        # INTELLIGENCE
        # ==========================
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
        results["anomalies"] = anomaly_engine.detect(results)

        # ==========================
        # RISK
        # ==========================
        risk_engine = RiskScoring()
        final_risk = risk_engine.calculate(
            results.get("risk_score", 0),
            "pipeline",
            nvd_cves,
            len(results["anomalies"])
        )

        results["final_risk_score"] = min(round(final_risk, 2), 10)

        exposure = ExposureClassifier()
        results["exposure_level"] = exposure.classify(results["final_risk_score"])

        confidence_engine = ConfidenceEngine()
        results["confidence_score"] = confidence_engine.calculate(results)

        # ==========================
        # AI PAYLOAD + EXPLOIT + ADAPT
        # ==========================
        payload_engine = PayloadEngine()
        results["ai_payloads"] = payload_engine.generate(results)

        exploit_engine = ExploitEngine()
        results["ai_exploits"] = exploit_engine.suggest(results,target)

        adaptive_engine = AdaptiveEngine()
        results["adaptive_actions"] = adaptive_engine.adapt(results)

        # ==========================
        # ATTACK LOGIC
        # ==========================
        reasoner = VulnerabilityReasoner()
        results["vulnerability_analysis"] = reasoner.analyze(results)

        chain_builder = AttackChainBuilder()
        results["attack_paths"] = chain_builder.generate(results)

        simulator = AttackSimulator()
        results["attack_simulation"] = simulator.simulate(results)

        post = PostExploitSimulator()
        results["post_exploitation"] = post.simulate(results)

        graph = AttackGraph()
        results["attack_graph"] = graph.generate(results)

        visualizer = GraphVisualizer()
        graph_file = visualizer.generate(target, results["attack_paths"])
        results["attack_graph_visualization"] = graph_file

        exploit_mapper = ExploitMapper()
        results["exploit_suggestions"] = exploit_mapper.suggest(results)

        # ==========================
        # AI REPORT
        # ==========================
        ai_engine = AIReportEngine()
        results["ai_report"] = ai_engine.generate(target, results)

        print("\n============================================================")
        print("🤖 AI GENERATED SECURITY REPORT")
        print("============================================================\n")
        print(results["ai_report"])

        # ==========================
        # EXPORT
        # ==========================
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