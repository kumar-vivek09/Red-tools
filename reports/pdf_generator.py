# reports/pdf_generator.py

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import os


def generate_pdf(context):

    os.makedirs("reports", exist_ok=True)

    filename = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
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