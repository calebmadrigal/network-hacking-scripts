#!/usr/bin/env python3

import sys
import argparse
from scapy.all import *


def get_mac(ip, interface):
    result = ''
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    ans, unans = srp(arp_request, timeout=2, iface=interface)
    if ans:
        first_response = ans[0]
        req, res = first_response
        result = res.getlayer(Ether).src

    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('victim_ip', type=str,
                        help='IP of the host you want to arp ping')
    parser.add_argument('-i', '--interface', type=str, dest='interface', default='wlan0',
                        help='Network interface to use')
    args = parser.parse_args()
    print("IP {} = MAC {}".format(args.victim_ip, get_mac(args.victim_ip, args.interface)))

