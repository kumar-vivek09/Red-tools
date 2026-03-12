import requests


class NVDEngine:

    def search(self, keyword):

        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=3"
            r = requests.get(url, timeout=10)

            if r.status_code != 200:
                return []

            data = r.json()
            cves = []

            for item in data.get("vulnerabilities", []):

                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")

                metrics = cve_data.get("metrics", {})
                cvss_score = 0

                # Try CVSS v3.1
                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

                elif "cvssMetricV30" in metrics:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

                elif "cvssMetricV2" in metrics:
                    cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                cves.append({
                    "cve_id": cve_id,
                    "cvss": cvss_score
                })

            return cves

        except:
            return []