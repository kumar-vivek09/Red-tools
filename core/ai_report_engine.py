class AIReportEngine:

    def generate(self, target, results):

        open_ports = results.get("open_ports", [])
        tech = results.get("technologies", [])
        risk = results.get("final_risk_score", 0)
        exposure = results.get("exposure_level", "Unknown")

        ffuf = results.get("ffuf", [])
        nuclei = results.get("nuclei", [])
        nikto = results.get("nikto", {})
        dalfox = results.get("dalfox", {})
        katana = results.get("katana_urls", [])
        subs = results.get("assetfinder_subdomains", [])

        attack_paths = results.get("attack_paths", [])

        # =================================================
        # EXECUTIVE SUMMARY (DYNAMIC)
        # =================================================

        findings = []

        if open_ports:
            findings.append("open network services detected")

        if tech:
            findings.append("web technologies identified")

        if ffuf:
            findings.append("hidden directories discovered")

        if nuclei:
            findings.append("potential vulnerabilities detected")

        if subs:
            findings.append("subdomains identified")

        if not findings:
            exec_summary = (
                f"The target {target} shows minimal external exposure. "
                f"No major services or vulnerabilities were detected."
            )
        else:
            exec_summary = (
                f"The assessment of {target} revealed {', '.join(findings)}. "
                f"This indicates a measurable attack surface that could be explored by attackers. "
                f"The overall exposure level is {exposure}."
            )

        # =================================================
        # TECHNICAL FINDINGS
        # =================================================

        tech_section = []

        if open_ports:
            tech_section.append(f"- Open Ports: {open_ports}")

        if tech:
            tech_section.append(f"- Technologies: {tech}")

        if subs:
            tech_section.append(f"- Subdomains: {subs[:5]}")

        if katana:
            tech_section.append(f"- Crawled URLs: {katana[:5]}")

        if ffuf:
            tech_section.append(f"- Directory Findings: {str(ffuf)[:200]}")

        if nuclei:
            tech_section.append(f"- Vulnerabilities: {str(nuclei)[:200]}")

        if nikto:
            tech_section.append("- Nikto scan completed (web misconfigurations checked)")

        if dalfox:
            tech_section.append("- Dalfox scan completed (XSS testing performed)")

        if not tech_section:
            tech_section.append("No significant technical findings.")

        tech_summary = "\n".join(tech_section)

        # =================================================
        # RISK ANALYSIS
        # =================================================

        if risk >= 7:
            risk_text = "High risk – Immediate remediation required."
        elif risk >= 4:
            risk_text = "Medium risk – Should be addressed soon."
        else:
            risk_text = "Low risk – Minimal exposure but monitoring recommended."

        # =================================================
        # ATTACK NARRATIVE (SMART)
        # =================================================

        if attack_paths:
            attack_story = "\n".join([f"- {path}" for path in attack_paths])
        else:
            attack_story = "No clear attack path identified."

        # =================================================
        # RECOMMENDATIONS (VERY IMPORTANT)
        # =================================================

        recommendations = []

        if open_ports:
            recommendations.append("Restrict unnecessary open ports using firewall rules.")

        if tech:
            recommendations.append("Keep all technologies updated and patched.")

        if ffuf:
            recommendations.append("Protect sensitive directories and disable directory listing.")

        if nuclei:
            recommendations.append("Immediately patch identified vulnerabilities.")

        if not recommendations:
            recommendations.append("Maintain current security posture and perform periodic scans.")

        rec_text = "\n".join([f"- {r}" for r in recommendations])

        # =================================================
        # FINAL REPORT
        # =================================================

        report = f"""
================ AI SECURITY REPORT ================

Target: {target}

================ EXECUTIVE SUMMARY ================
{exec_summary}

================ TECHNICAL FINDINGS ===============
{tech_summary}

================ RISK ANALYSIS ====================
Score: {risk}
Level: {exposure}
Assessment: {risk_text}

================ ATTACK PATH ======================
{attack_story}

================ RECOMMENDATIONS ==================
{rec_text}

==================================================
"""

        return report