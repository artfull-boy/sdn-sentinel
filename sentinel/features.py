
#!/usr/bin/env python3
"""
Sentinel feature module: turns raw ONOS snapshots into 12 features per edge port over a 10 s window (5 steps of 2 s). Same code for training and live detection.

Build the training table:  python sentinel/features.py <recordings folder> --labels <labels.jsonl> --out features.csv

"""

import argparse
import csv
import glob
import json
import os
import statistics
import sys
from collections import deque

WINDOW_STEPS = 5          # 5 steps x 2 s = 10 s window

FEATURES = [
    "new_flows",            # 1  new flow ids on this port, summed over the window
    "new_flows_max_step",   # 2  largest single-step new-flow count
    "burstiness",           # 3  std dev of the per-step new-flow counts
    "active_steps",         # 4  steps with at least one new flow
    "uniq_src_mac",         # 5  distinct ETH_SRC in flows on this port during the window
    "uniq_dst_mac",         # 6  distinct ETH_DST in flows on this port during the window
    "rx_pkts",              # 7  packets received on this port during the window
    "flows_per_pkt",        # 8  new_flows / rx_pkts (0 when rx_pkts is 0)
    "hosts_on_port",        # 9  hosts ONOS places on this port at window end
    "host_moves_in",        # 10 hosts arriving on this port from their home port (see FeatureWindow)
    "table_size_sw",        # 11 flow rules on this port's switch at window end
    "table_growth",         # 12 table_size_sw at window end minus at window start
]

ID_COLS = ["ts", "run_id", "switch", "port"]
OUT_COLS = ID_COLS + FEATURES + ["label", "split", "phase"]

# Runs recorded as tests on Nov 7; too short to be real runs.
EXCLUDE_RUNS = {"S5_20261107_095405", "S1_20261107_095637"}


# --------------------------------------------------------------------------
# Live and offline core
# --------------------------------------------------------------------------

def _s(x):
    return None if x is None else str(x)


def core_ports_from_links(links):
    """Set of (dev, port) that are switch-to-switch ports."""
    core = set()
    for link in links or []:
        for end in (link.get("src"), link.get("dst")):
            if end and "/" in end:
                dev, port = end.rsplit("/", 1)
                core.add((dev, port))
    return core


def _digest(sample):
    """Reduce one raw snapshot to the small per-port facts the features need.
    Keeps memory low during floods (thousands of flows per snapshot)."""
    flows_by_port = {}      # (dev, port) -> set of flow ids
    src_by_port = {}        # (dev, port) -> set of src MACs
    dst_by_port = {}        # (dev, port) -> set of dst MACs
    table_size = {}         # dev -> number of flow rules
    for f in sample.get("flows", []):
        dev = f.get("dev")
        table_size[dev] = table_size.get(dev, 0) + 1
        inport = _s(f.get("inport"))
        if inport is None:
            continue
        key = (dev, inport)
        flows_by_port.setdefault(key, set()).add(f.get("id"))
        if f.get("ethsrc"):
            src_by_port.setdefault(key, set()).add(f["ethsrc"].lower())
        if f.get("ethdst"):
            dst_by_port.setdefault(key, set()).add(f["ethdst"].lower())

    rx = {}
    for p in sample.get("ports", []):
        port = _s(p.get("port"))
        if port is None or port.upper() == "LOCAL":
            continue
        rx[(p.get("dev"), port)] = p.get("rx", 0) or 0

    host_loc = {}           # mac -> (dev, port)
    for h in sample.get("hosts", []):
        if h.get("mac") and h.get("dev"):
            host_loc[h["mac"].lower()] = (h["dev"], _s(h.get("port")))

    return {"ts": float(sample["ts"]), "flows": flows_by_port,
            "src": src_by_port, "dst": dst_by_port, "table": table_size,
            "rx": rx, "hosts": host_loc}


class FeatureWindow:
    """Sliding window over snapshots. push() one snapshot at a time; once
    WINDOW_STEPS + 1 snapshots are held, every push returns one feature row
    per edge port (a list of dicts with ts, switch, port and the 12 features)."""

    def __init__(self, links, window_steps=WINDOW_STEPS):
        self.core = core_ports_from_links(links)
        self.steps = window_steps
        self.buf = deque(maxlen=window_steps + 1)
        # Home port of each host = the first place we saw it. During spoofing ONOS
        # flips the victim's MAC between the attacker's port and the victim's own
        # port; only arrivals AWAY from home count, so the victim's port is not
        # blamed when its own host flips back.
        self.home = {}

    def edge_ports(self):
        ports = set()
        for d in self.buf:
            ports.update(d["rx"].keys())
        return sorted(p for p in ports if p not in self.core)

    def push(self, sample):
        digest = _digest(sample)
        for mac, loc in digest["hosts"].items():
            self.home.setdefault(mac, loc)
        self.buf.append(digest)
        if len(self.buf) < self.steps + 1:
            return []
        return [self._row(key) for key in self.edge_ports()]

    def _row(self, key):
        dev, port = key
        snaps = list(self.buf)
        first, last = snaps[0], snaps[-1]

        per_step = []
        moves_in = 0
        for prev, cur in zip(snaps, snaps[1:]):
            before = prev["flows"].get(key, set())
            now = cur["flows"].get(key, set())
            per_step.append(len(now - before))
            for mac, loc in cur["hosts"].items():
                if (loc == key and prev["hosts"].get(mac) not in (None, key)
                        and self.home.get(mac) != key):
                    moves_in += 1

        src, dst = set(), set()
        for d in snaps:
            src |= d["src"].get(key, set())
            dst |= d["dst"].get(key, set())

        new_flows = sum(per_step)
        rx_pkts = max(0, last["rx"].get(key, 0) - first["rx"].get(key, 0))
        table_end = last["table"].get(dev, 0)

        return {
            "ts": last["ts"],
            "switch": dev,
            "port": port,
            "new_flows": new_flows,
            "new_flows_max_step": max(per_step),
            "burstiness": round(statistics.pstdev(per_step), 4),
            "active_steps": sum(1 for n in per_step if n > 0),
            "uniq_src_mac": len(src),
            "uniq_dst_mac": len(dst),
            "rx_pkts": rx_pkts,
            "flows_per_pkt": round(new_flows / rx_pkts, 6) if rx_pkts else 0.0,
            "hosts_on_port": sum(1 for loc in last["hosts"].values() if loc == key),
            "host_moves_in": moves_in,
            "table_size_sw": table_end,
            "table_growth": table_end - first["table"].get(dev, 0),
        }


def vector(row):
    """The 12 features of a row as a list, in the fixed model order."""
    return [row[f] for f in FEATURES]


# --------------------------------------------------------------------------
# Offline: recordings -> labelled training table
# --------------------------------------------------------------------------

def features_from_file(path):
    """Stream one recording (line by line) and return (run_id, rows)."""
    run_id = os.path.splitext(os.path.basename(path))[0]
    fw, rows = None, []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("type") == "meta":
                run_id = obj.get("run_id") or run_id
                fw = FeatureWindow(obj.get("links", []))
            elif obj.get("type") == "sample":
                if fw is None:
                    fw = FeatureWindow([])
                rows.extend(fw.push(obj))
    for r in rows:
        r["run_id"] = run_id
    return run_id, rows


def load_labels(path):
    out = []
    with open(path) as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


def match_label(run_id, rows, labels, filename=None):
    """Find this recording's label line: by run id or file name first,
    otherwise by time (the label's interval that overlaps the recording most)."""
    names = {run_id, filename}
    for lab in labels:
        if lab["run_id"] in names:
            return lab
    if not rows:
        return None
    t0, t1 = rows[0]["ts"], rows[-1]["ts"]
    best, best_overlap = None, 0.0
    for lab in labels:
        overlap = min(t1, lab["t_end"]) - max(t0, lab["t_start"])
        if overlap > best_overlap:
            best, best_overlap = lab, overlap
    return best


def label_rows(rows, lab, window_s):
    """Label rule from data/Readme.md: the run's label only on the attacker
    port, for windows that overlap the attack; everything else is normal.
    `phase` says where in the run a row sits: normal_run, pre, attack, post."""
    attack = lab and lab.get("label") != "normal" and lab.get("attacker")
    for r in rows:
        r["label"] = "normal"
        if not attack:
            r["phase"] = "normal_run"
            continue
        w_end, w_start = r["ts"], r["ts"] - window_s
        if w_end < lab["t_start"]:
            r["phase"] = "pre"
        elif w_start > lab["t_end"]:
            r["phase"] = "post"
        else:
            r["phase"] = "attack"
            if "%s:%s" % (r["switch"], r["port"]) == lab["attacker"]:
                r["label"] = lab["label"]


def assign_splits(runs):
    """runs: list of (label_line, rows). Normal runs are split by time inside
    each run (60/20/20), because there are too few normal runs to split by run.
    Attack runs are split by run, per scenario, oldest first: the last 2 runs
    are test, the one before is validation, the rest train."""
    by_scenario = {}
    for lab, rows in runs:
        if lab and lab.get("label") != "normal":
            by_scenario.setdefault(lab["scenario"], []).append((lab, rows))
        else:
            n = len(rows)
            for i, r in enumerate(rows):
                r["split"] = "train" if i < 0.6 * n else ("val" if i < 0.8 * n else "test")
    for group in by_scenario.values():
        group.sort(key=lambda x: x[0]["t_start"])
        n = len(group)
        for i, (lab, rows) in enumerate(group):
            split = "test" if i >= n - 2 else ("val" if i == n - 3 else "train")
            for r in rows:
                r["split"] = split


def build_table(paths, labels_path, out_path, step_s=2.0):
    labels = load_labels(labels_path) if labels_path else []
    window_s = WINDOW_STEPS * step_s
    runs = []
    for path in paths:
        name = os.path.splitext(os.path.basename(path))[0]
        run_id, rows = features_from_file(path)
        lab = match_label(run_id, rows, labels, filename=name)
        rid = lab["run_id"] if lab else run_id
        if rid in EXCLUDE_RUNS or run_id in EXCLUDE_RUNS:
            print("skip   %-28s (excluded test run)" % name, file=sys.stderr)
            continue
        if lab is None:
            print("skip   %-28s (no matching line in labels)" % name, file=sys.stderr)
            continue
        for r in rows:
            r["run_id"] = rid
        label_rows(rows, lab, window_s)
        runs.append((lab, rows))
        n_att = sum(1 for r in rows if r["label"] != "normal")
        print("ok     %-28s -> %-22s %-16s %5d rows, %4d attack rows"
              % (name, rid, lab["label"], len(rows), n_att), file=sys.stderr)
    assign_splits(runs)
    with open(out_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=OUT_COLS, extrasaction="ignore")
        w.writeheader()
        for _, rows in runs:
            w.writerows(rows)
    total = sum(len(rows) for _, rows in runs)
    print("wrote %d rows from %d runs to %s" % (total, len(runs), out_path), file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description="Build the Sentinel feature table")
    p.add_argument("inputs", nargs="+", help=".jsonl files or folders holding them")
    p.add_argument("--labels", help="data/labels.jsonl")
    p.add_argument("--out", default="features.csv")
    p.add_argument("--step", type=float, default=2.0, help="seconds between snapshots")
    a = p.parse_args()
    paths = []
    for x in a.inputs:
        if os.path.isdir(x):
            paths += glob.glob(os.path.join(x, "**", "*.jsonl"), recursive=True)
        else:
            paths.append(x)
    paths = sorted(p for p in paths if os.path.basename(p) != "labels.jsonl")
    if not paths:
        sys.exit("no .jsonl recordings found")
    build_table(paths, a.labels, a.out, a.step)


if __name__ == "__main__":
    main()
