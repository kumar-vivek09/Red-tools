# module/intelligence/reverse_dns.py

import socket


class ReverseDNS:

    def lookup(self, ip):

        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None