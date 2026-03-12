import requests


class ShodanEngine:

    def __init__(self, api_key):
        self.api_key = api_key

    def lookup(self, ip):

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
            r = requests.get(url, timeout=10)

            if r.status_code != 200:
                return {}

            data = r.json()

            return {
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", []))
            }

        except:
            return {}