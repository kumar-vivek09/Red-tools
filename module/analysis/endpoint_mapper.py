# module/analysis/endpoint_mapper.py

import re
import requests
from urllib.parse import urljoin

def map_endpoints(target):

    discovered = []

    try:
        base_url = f"http://{target}"
        response = requests.get(base_url, timeout=5)

        links = re.findall(r'href=["\'](.*?)["\']', response.text)

        for link in links:

            if link.startswith("#"):
                continue

            full_url = urljoin(base_url, link)
            discovered.append(full_url)

        return list(set(discovered))

    except Exception:
        return []