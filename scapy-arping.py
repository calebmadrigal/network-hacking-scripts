#!/usr/bin/env python3

import sys
from scapy.all import *


def get_mac(ip):
    result = ''
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    ans, unans = srp(arp_request, timeout=2)
    if ans:
        first_response = ans[0]
        req, res = first_response
        result = res.getlayer(Ether).src

    return result


if __name__ == '__main__':
    try:
        victim_ip = sys.argv[1]

    except IndexError:
        print("Usage: {} <victim ip>".format(sys.argv[0]))
        sys.exit(1)

    print("Victim mac: {}".format(get_mac(victim_ip)))


