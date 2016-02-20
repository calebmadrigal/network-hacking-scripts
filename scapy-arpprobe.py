#!/usr/bin/env python3
#
# Code from: http://bit.ly/1JwUPiM

import argparse
from scapy.all import *


def arp_display(pkt):
    if pkt[ARP].op == 1: #who-has (request)
        if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
            print("ARP Probe from: " + pkt[ARP].hwsrc)


def sniff_arpprobe(interface):
    try:
        sniff(iface=interface, prn=arp_display, filter="arp", store=0, count=10)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, dest='interface', default='wlan0',
                        help='Network interface to use')
    args = parser.parse_args()
    print('Sniffing for ARP Probe packets on interface: {}'.format(args.interface))
    sniff_arpprobe(args.interface)

