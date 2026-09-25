#!/usr/bin/env python3
# ==============================================================================
# File Name:     traceroute.py
# Author:        Eva Tate and Giselle Wu
# Course:        CS60: Computer Networks
# Assignment:    Lab 1: Packet sniffing and spoofing
# Date:          September 29, 2026
# 
# Description:   Implements a traceroute program described in Lab 1, Exercise 2.
# 
# ==============================================================================

"""Traceroute tool using Scapy.

Usage: sudo python3 traceroute.py <target ip or domain>
"""

import socket
import sys

from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1

MAX_HOPS = 30
TIMEOUT = 2


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target ip or domain>")
        sys.exit(1)

    target = sys.argv[1]
    dest_ip = socket.gethostbyname(target)
    print(f"traceroute to {target} ({dest_ip}), {MAX_HOPS} hops max")

    for ttl in range(1, MAX_HOPS + 1):
        pkt = IP(dst=dest_ip, ttl=ttl) / ICMP(id=1, seq=ttl)
        reply = sr1(pkt, timeout=TIMEOUT, verbose=0)

        if reply is None:
            print(f"{ttl}\t*")
            continue

        hop_ip = reply.src
        try:
            hop_name = socket.gethostbyaddr(hop_ip)[0]
        except socket.herror:
            hop_name = hop_ip

        print(f"{ttl}\t{hop_name} ({hop_ip})")

        if reply.type == 0 or hop_ip == dest_ip:
            break
    else:
        print(f"Destination not reached after {MAX_HOPS} hops")


if __name__ == "__main__":
    main()
