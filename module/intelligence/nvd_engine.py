import requests

class NVDEngine:

    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def run(self, technologies):
        cves = []

        try:
            for tech in technologies:
                keyword = tech.split()[0]  # Apache, PHP

                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": 3
                }

                response = requests.get(self.base_url, params=params, timeout=10)

                if response.status_code == 200:
                    data = response.json()

                    for item in data.get("vulnerabilities", []):
                        cve_id = item["cve"]["id"]

                        cves.append({
                            "cve_id": cve_id
                        })

        except Exception as e:
            print("NVD Error:", e)

        return {"nvd_cves": cves}