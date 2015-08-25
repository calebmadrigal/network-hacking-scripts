#!/usr/bin/env python3
#
# Code from: http://bit.ly/1JwUPiM

from scapy.all import *

def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      print("ARP Probe from: " + pkt[ARP].hwsrc)

sniff(prn=arp_display, filter="arp", store=0, count=10)
