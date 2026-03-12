# module/analysis/cookie_inspector.py

import requests

def inspect_cookies(target):

    cookie_analysis = []

    try:
        response = requests.get(f"http://{target}", timeout=5)

        for cookie in response.cookies:
            cookie_data = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie._rest.get("HttpOnly", False),
                "path": cookie.path
            }

            cookie_analysis.append(cookie_data)

        return cookie_analysis

    except Exception:
        return []