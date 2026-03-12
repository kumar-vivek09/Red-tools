# ui/cli.py

import argparse
from core.orchestrator import Orchestrator
from reports.json_exporter import export_json
from reports.pdf_generator import generate_pdf


def run_cli():

    parser = argparse.ArgumentParser(
        prog="ARCHAI",
        description="AI Orchestrated Recon & Attack Surface Intelligence Framework"
    )

    parser.add_argument("command", help="scan")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--report", choices=["json", "pdf"])

    args = parser.parse_args()

    if args.command == "scan":

        engine = Orchestrator(args.target)
        context = engine.run()

        if args.report == "json":
            file = export_json(context)
            print(f"[+] JSON report saved to {file}")

        elif args.report == "pdf":
            file = generate_pdf(context)
            print(f"[+] PDF report saved to {file}")