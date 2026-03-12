# module/intelligence/asn_lookup.py

import socket
import requests


class ASNLookup:

    def lookup(self, target):

        try:
            ip = socket.gethostbyname(target)
        except:
            return {}

        try:
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=5
            )

            data = response.json()

            return {
                "ip": ip,
                "asn": data.get("org"),
                "country": data.get("country")
            }

        except:
            return {
                "ip": ip,
                "asn": None,
                "country": None
            }