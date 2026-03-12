# module/analysis/header_analyzer.py

import requests

SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def analyze_headers(target):

    findings = {
        "missing_headers": [],
        "server_banner": None,
        "powered_by": None
    }

    try:
        response = requests.get(f"http://{target}", timeout=5)
        headers = response.headers

        # Missing headers
        for header in SECURITY_HEADERS:
            if header not in headers:
                findings["missing_headers"].append(header)

        # Server banner detection
        if "Server" in headers:
            findings["server_banner"] = headers["Server"]

        if "X-Powered-By" in headers:
            findings["powered_by"] = headers["X-Powered-By"]

        return findings

    except Exception:
        return findings