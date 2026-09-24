#!/usr/bin/env python3
"""Ping tool using Scapy.

Usage: sudo python3 ping.py <target ip or domain>
"""

import socket
import sys
import time

from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr1


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target ip or domain>")
        sys.exit(1)

    target = sys.argv[1]
    dest_ip = socket.gethostbyname(target)
    print(f"PING {target} ({dest_ip})")

    seq = 1
    rtts = []
    sent = 0
    received = 0

    try:
        while True:
            pkt = IP(dst=dest_ip) / ICMP(id=1, seq=seq)
            send_time = time.time()
            sent += 1
            reply = sr1(pkt, timeout=2, verbose=0)
            recv_time = time.time()

            if reply is not None:
                rtt_ms = (recv_time - send_time) * 1000
                rtts.append(rtt_ms)
                received += 1
                print(f"64 bytes from {dest_ip}: icmp_seq={seq} time={rtt_ms:.3f} ms")
            else:
                print(f"Request timeout for icmp_seq={seq}")

            seq += 1
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n--- {target} ping statistics ---")
        loss_pct = 100 * (sent - received) / sent if sent else 0
        print(f"{sent} packets transmitted, {received} received, {loss_pct:.1f}% packet loss")
        if rtts:
            avg = sum(rtts) / len(rtts)
            print(f"rtt min/avg/max = {min(rtts):.3f}/{avg:.3f}/{max(rtts):.3f} ms")


if __name__ == "__main__":
    main()
