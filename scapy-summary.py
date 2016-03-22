#!/usr/bin/env python3

import argparse
from scapy.all import *


def sniff_arpprobe(interface, host=None):
    filter_str = ''
    if host:
        filter_str = 'host {}'.format(host)
    try:
        sniff(iface=interface, filter=filter_str, prn=lambda p: p.summary(), store=0)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, dest='interface', default='wlan0',
                        help='Network interface to use')
    parser.add_argument('-t', '--target', type=str, dest='target',
                        help='Target host to sniff')
    args = parser.parse_args()
    print('Sniffing on interface: {}'.format(args.interface))
    sniff_arpprobe(args.interface, args.target)

