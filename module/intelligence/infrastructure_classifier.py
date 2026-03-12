# module/intelligence/infrastructure_classifier.py


class InfrastructureClassifier:

    CDN_KEYWORDS = [
        "cloudflare",
        "akamai",
        "fastly",
        "incapsula"
    ]

    CLOUD_KEYWORDS = [
        "amazon",
        "aws",
        "google",
        "microsoft",
        "azure",
        "digitalocean",
        "linode"
    ]

    def classify(self, asn_string):

        if not asn_string:
            return "unknown"

        asn_string = asn_string.lower()

        if any(keyword in asn_string for keyword in self.CDN_KEYWORDS):
            return "cdn"

        if any(keyword in asn_string for keyword in self.CLOUD_KEYWORDS):
            return "cloud"

        return "dedicated_or_unknown"