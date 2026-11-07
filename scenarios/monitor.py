#!/usr/bin/env python3
"""
Security of SDN - Lab 2: ONOS monitoring via the REST API.

Polls ONOS once a second and prints, for the whole network:
  - flows      : total number of flow rules across all switches
  - new/s      : how many flow rules were added since the previous second
  - pktin/s    : packets hitting the IPv4 "send-to-controller" catch-all rule
                 per second = a proxy for the PACKET_IN rate (the controller's load)

Watch these numbers while the network is calm (baseline), then during an attack.
During a random-source flood, new/s and pktin/s explode, because every packet
is a brand-new flow that the switch must ask the controller about.

Usage:
  python3 monitor.py                 # print to screen
  python3 monitor.py --csv base.csv  # also append each second to a CSV file

Stop with Ctrl+C.
"""

import argparse
import base64
import csv
import json
import sys
import time
import urllib.request

ONOS = "http://localhost:8181/onos/v1"
USER, PASSWORD = "onos", "rocks"

# The catch-all rule we track sends unknown IPv4 to the controller.
# In ONOS it shows as selector ETH_TYPE:ipv4 with priority 5.
CATCHALL_PRIORITY = 5
CATCHALL_ETHTYPE = "IPV4"


def get(path):
    """GET a REST resource and return the parsed JSON."""
    req = urllib.request.Request(ONOS + path)
    token = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)


def is_catchall(flow):
    """True if this flow is the priority-5 'IPv4 -> CONTROLLER' catch-all."""
    if flow.get("priority") != CATCHALL_PRIORITY:
        return False
    for crit in flow.get("selector", {}).get("criteria", []):
        if crit.get("type") == "ETH_TYPE" and str(crit.get("ethType", "")).upper().endswith("800"):
            return True
        if crit.get("type") == "ETH_TYPE" and str(crit.get("ethType", "")).upper() == CATCHALL_ETHTYPE:
            return True
    return False


def snapshot():
    """Return (total_flow_count, total_catchall_packets) right now."""
    data = get("/flows")
    flows = data.get("flows", [])
    total_flows = len(flows)
    catchall_packets = 0
    for f in flows:
        if is_catchall(f):
            catchall_packets += f.get("packets", 0)
    return total_flows, catchall_packets


def main():
    ap = argparse.ArgumentParser(description="ONOS REST monitor for Lab 2")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds between polls")
    ap.add_argument("--csv", help="append rows to this CSV file")
    args = ap.parse_args()

    writer = None
    csv_file = None
    if args.csv:
        csv_file = open(args.csv, "a", newline="")
        writer = csv.writer(csv_file)
        if csv_file.tell() == 0:
            writer.writerow(["time", "flows", "new_per_s", "pktin_per_s"])

    print("Monitoring ONOS. Ctrl+C to stop.\n")
    print(f"{'time':>8} | {'flows':>6} | {'new/s':>6} | {'pktin/s':>8}")
    print("-" * 38)

    prev_flows, prev_catchall = None, None
    try:
        while True:
            try:
                flows, catchall = snapshot()
            except Exception as e:
                print(f"  (poll failed: {e})", file=sys.stderr)
                time.sleep(args.interval)
                continue

            if prev_flows is None:
                new_s, pktin_s = 0, 0
            else:
                new_s = max(0, flows - prev_flows)
                pktin_s = max(0, catchall - prev_catchall)
            prev_flows, prev_catchall = flows, catchall

            now = time.strftime("%H:%M:%S")
            print(f"{now:>8} | {flows:>6} | {new_s:>6} | {pktin_s:>8}")
            if writer:
                writer.writerow([now, flows, new_s, pktin_s])
                csv_file.flush()

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    main()
