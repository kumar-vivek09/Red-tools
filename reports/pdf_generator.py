# reports/pdf_generator.py

import os
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
except Exception:
    A4 = None
    SimpleDocTemplate = None
    Paragraph = None
    Spacer = None
    getSampleStyleSheet = None


def generate_pdf(context):

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/report_{timestamp}.pdf"

    if SimpleDocTemplate is None or Paragraph is None or Spacer is None or getSampleStyleSheet is None:
        fallback_path = f"reports/report_{timestamp}.txt"
        with open(fallback_path, "w", encoding="utf-8") as handle:
            handle.write(str(context))
        return fallback_path

    doc = SimpleDocTemplate(filename, pagesize=A4)
    elements = []

    styles = getSampleStyleSheet()

    elements.append(Paragraph("ARCHAI Security Report", styles["Title"]))
    elements.append(Spacer(1, 20))

    for key, value in context.items():
        elements.append(Paragraph(f"<b>{key}</b>: {str(value)}", styles["Normal"]))
        elements.append(Spacer(1, 10))

    doc.build(elements)

    return filename