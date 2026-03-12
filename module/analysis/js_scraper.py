# module/analysis/js_scraper.py

import re
import requests
from urllib.parse import urljoin

def scrape_js(target):

    js_files = []
    endpoints = []

    try:
        base_url = f"http://{target}"
        response = requests.get(base_url, timeout=5)

        # Find script sources
        scripts = re.findall(r'<script.*?src=["\'](.*?)["\']', response.text)

        for script in scripts:
            full_url = urljoin(base_url, script)
            js_files.append(full_url)

            try:
                js_response = requests.get(full_url, timeout=5)

                # Extract endpoints from JS
                found = re.findall(r'["\'](/api/.*?|/v\d+/.*?)["\']', js_response.text)
                endpoints.extend(found)

            except:
                continue

        return {
            "js_files": js_files,
            "js_endpoints": list(set(endpoints))
        }

    except Exception:
        return {
            "js_files": [],
            "js_endpoints": []
        }