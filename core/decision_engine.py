# core/decision_engine.py

class DecisionEngine:

    def __init__(self):
        pass

    def evaluate(self, context):
        """
        Analyze context and determine next actions.
        """

        actions = []

        # Port-based logic
        if 80 in context.get("open_ports", []) or 443 in context.get("open_ports", []):
            actions.append("tech_detect")

        if 22 in context.get("open_ports", []):
            actions.append("ssh_analysis")

        # Technology-based logic
        for tech in context.get("technologies", []):
            if "Apache" in tech:
                actions.append("apache_checks")

            if "PHP" in tech:
                actions.append("php_analysis")

        # Header-based logic
        if len(context.get("header_issues", [])) > 2:
            actions.append("misconfig_detection")

        return list(set(actions))


    def calculate_priority(self, context):
        """
        Assign weighted priority to findings.
        """

        priority_score = 0

        priority_score += len(context.get("open_ports", [])) * 2
        priority_score += len(context.get("header_issues", [])) * 3
        priority_score += len(context.get("subdomains", [])) * 1

        return min(priority_score, 100)