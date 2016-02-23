#!/usr/bin/env python3

import dnslib
import argparse
from scapy.all import *

try:
    from termcolor import colored
except ImportError:
    colored = lambda msg, color: msg


def show_packet(pkt):
    if ARP in pkt:
        print(pkt.summary())

        if pkt[ARP].op == 1: #who-has (request)
            if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
                print(colored('\tARP Probe from: ' + pkt[ARP].hwsrc, 'red'))
    elif UDP in pkt:
        print(repr(pkt))

        # Try to show mDNS info
        try:
            raw_load = pkt.getlayer(3).load 
            dns_parsed = dnslib.DNSRecord.parse(raw_load) 
            if dns_parsed.header.ar > 0:
                mdns_name = [i.rname for i in dns_parsed.ar]
                print(colored('\tmDNS Name: {}'.format(repr(mdns_name)), 'red'))
        except Exception as e:
            print('ERROR: {}'.format(e))
    else:
        print(repr(pkt))


def watch_network(interface):
    try:
        sniff(iface=interface, prn=show_packet, filter="arp or (udp port 53) or (udp port 5353)", store=0)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', type=str, dest='interface', default='wlan0',
                        help='Network interface to use')
    args = parser.parse_args()
    print('Sniffing on interface: {}'.format(args.interface))
    watch_network(args.interface)

