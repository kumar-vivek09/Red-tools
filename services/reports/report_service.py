"""Report generation service wrappers."""

from core.report_generator import ReportGenerator
from reports.json_exporter import export_json
from reports.pdf_generator import generate_pdf


class ReportService:
    """Generate and export reports while keeping legacy outputs intact."""

    def generate_json_report(self, target, results):
        return ReportGenerator().generate(target, results)

    def export_json(self, context):
        return export_json(context)

    def generate_pdf(self, context):
        return generate_pdf(context)
