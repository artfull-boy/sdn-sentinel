#!/usr/bin/env python3
"""
Sentinel: raw ONOS state recorder.

Snapshots the controller's state once per second to a JSONL file, so the
dataset can be built WITHOUT computing features here. Aishwarya runs her own
features.py over this raw capture to produce the training CSV, which is the
exact same feature code her live detector uses. That avoids train/serve skew
(features computed one way for training, another way live).

Run this in one terminal while run_scenario.py plays a run in another. Stop it
with Ctrl+C when the run finishes (or pass --duration to auto-stop).

FLAGS
  out              (positional) output JSONL file, e.g. data/raw/S4_run1.jsonl
  --interval N     seconds between snapshots (default 1.0). Use 2.0 if a poll
                   cannot keep up during a heavy flood (a warning is printed).
  --duration N     stop automatically after N seconds (default: run until Ctrl+C)

Pure standard library, no pip packages needed.

Usage:
  python3 scenarios/raw_recorder.py data/raw/S4_run1.jsonl
  python3 scenarios/raw_recorder.py data/raw/S1_run1.jsonl --interval 2 --duration 920
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.request

ONOS = "http://localhost:8181/onos/v1"
USER, PASSWORD = "onos", "rocks"


def get(path):
    """GET a REST resource and return parsed JSON."""
    req = urllib.request.Request(ONOS + path)
    token = base64.b64encode(("%s:%s" % (USER, PASSWORD)).encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)


def crit(criteria, kind, field):
    """Pull one selector criterion value (e.g. the IN_PORT port) or None."""
    for c in criteria:
        if c.get("type") == kind:
            return c.get(field)
    return None


def trim_flows():
    """Keep only the raw fields features.py needs from each flow:
    id (to diff second to second), device, in_port, eth_src, eth_dst, packets."""
    out = []
    for f in get("/flows").get("flows", []):
        criteria = f.get("selector", {}).get("criteria", [])
        out.append({
            "id": f.get("id"),
            "dev": f.get("deviceId"),
            "inport": crit(criteria, "IN_PORT", "port"),
            "ethsrc": crit(criteria, "ETH_SRC", "mac"),
            "ethdst": crit(criteria, "ETH_DST", "mac"),
            "pkts": f.get("packets", 0),
        })
    return out


def trim_ports():
    """Per device-port received/sent packet counters (for rx_pkts)."""
    out = []
    for dev in get("/statistics/ports").get("statistics", []):
        for p in dev.get("ports", []):
            out.append({
                "dev": dev.get("device"),
                "port": p.get("port"),
                "rx": p.get("packetsReceived", 0),
                "tx": p.get("packetsSent", 0),
            })
    return out


def trim_hosts():
    """Each host's MAC and where ONOS thinks it lives (for host moves)."""
    out = []
    for h in get("/hosts").get("hosts", []):
        loc = (h.get("locations") or [{}])[0]
        out.append({
            "mac": h.get("mac"),
            "dev": loc.get("elementId"),
            "port": loc.get("port"),
        })
    return out


def read_links():
    """Switch-to-switch links, captured once so features.py can tell edge
    ports from core ports without a second tool."""
    out = []
    for l in get("/links").get("links", []):
        s, d = l.get("src", {}), l.get("dst", {})
        out.append({"src": "%s/%s" % (s.get("device"), s.get("port")),
                    "dst": "%s/%s" % (d.get("device"), d.get("port"))})
    return out


def main():
    p = argparse.ArgumentParser(description="Sentinel raw ONOS state recorder")
    p.add_argument("out", help="output JSONL file")
    p.add_argument("--interval", type=float, default=1.0,
                   help="seconds between snapshots (default 1.0)")
    p.add_argument("--duration", type=int, default=None,
                   help="stop after N seconds (default: until Ctrl+C)")
    args = p.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    run_id = os.path.splitext(os.path.basename(args.out))[0]

    end = time.time() + args.duration if args.duration else None
    samples, slow = 0, 0
    f = open(args.out, "w")

    # First line is metadata: the run id and the static link list.
    try:
        links = read_links()
    except Exception as e:
        sys.exit("Cannot reach ONOS at %s (%s). Is the container up?" % (ONOS, e))
    f.write(json.dumps({"type": "meta", "run_id": run_id,
                        "started": round(time.time(), 3), "links": links}) + "\n")
    f.flush()

    print("recording %s every %.1fs (Ctrl+C to stop)" % (args.out, args.interval),
          flush=True)
    try:
        while end is None or time.time() < end:
            t0 = time.time()
            try:
                sample = {"type": "sample", "ts": round(t0, 3),
                          "flows": trim_flows(), "ports": trim_ports(),
                          "hosts": trim_hosts()}
            except Exception as e:
                print("  poll failed: %s" % e, file=sys.stderr, flush=True)
                time.sleep(args.interval)
                continue
            f.write(json.dumps(sample) + "\n")
            f.flush()
            samples += 1

            took = time.time() - t0
            if took > args.interval:
                slow += 1
                print("  warning: poll took %.2fs (> %.1fs). Use --interval 2."
                      % (took, args.interval), file=sys.stderr, flush=True)
            else:
                time.sleep(args.interval - took)
    except KeyboardInterrupt:
        pass
    finally:
        f.close()
    print("done: %d samples, %d slow polls, written to %s"
          % (samples, slow, args.out), flush=True)


if __name__ == "__main__":
    main()
