# module/intelligence/ai_classifier.py

def classify_target(context):

    score = context.get("risk_score", 0)

    classification = {
        "risk_level": "Low",
        "confidence": "Moderate",
        "summary": ""
    }

    if score >= 70:
        classification["risk_level"] = "Critical"
    elif score >= 40:
        classification["risk_level"] = "High"
    elif score >= 20:
        classification["risk_level"] = "Medium"
    else:
        classification["risk_level"] = "Low"

    # Intelligent summary generation (rule-based for now)
    summary_parts = []

    if context.get("open_ports"):
        summary_parts.append(
            f"{len(context['open_ports'])} open ports detected."
        )

    if context.get("header_analysis", {}).get("missing_headers"):
        summary_parts.append(
            "Security headers missing."
        )

    if context.get("cookie_analysis"):
        summary_parts.append(
            "Cookie security flags analyzed."
        )

    if context.get("mapped_endpoints"):
        summary_parts.append(
            "Multiple public endpoints discovered."
        )

    classification["summary"] = " ".join(summary_parts)

    return classification