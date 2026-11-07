#!/usr/bin/env python3
"""
Sentinel: scenario runner. Plays one labelled run on a fixed timeline and
records exactly when the attack happened, so the dataset can be labelled
offline without guessing.

Timeline for an attack run:
    [ normal 60s ] [ attack 60s ] [ recovery 60s ]
Normal traffic (traffic_gen.py) runs the WHOLE time. The attack is launched on
h1 only during the middle phase. One line is appended to data/labels.jsonl:
    {run_id, scenario, label, attacker, t_start, t_end}
t_start / t_end are epoch seconds bounding the attack window (the whole run for
a normal-only scenario), matching the collector's `ts` column so a later join
labels each feature row.

The collector (Aishwarya's, run with --record) runs ALONGSIDE this in another
terminal; this runner does not start it, so the two parts stay independent.

Scenarios:
    S0 idle     S1 pingall   S2 iperf    S3 mixed        (normal only)
    S4 flood    S5 slow      S6 pulsed   S7 spoofing     (attack in the middle)

Usage (topology running, collector recording in another terminal):
    sudo python3 scenarios/run_scenario.py S4
    sudo python3 scenarios/run_scenario.py S1 --duration 900     # long normal run
    sudo python3 scenarios/run_scenario.py S5 --normal 60 --attack 60 --recovery 60
"""

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ATTACK_DIR = os.path.join(HERE, "attacks")
REPO = os.path.dirname(HERE)
LABELS = os.path.join(REPO, "data", "labels.jsonl")

# h1 is always the attacker: switch of:0000000000000001, port 1.
ATTACKER = "of:0000000000000001:1"

# normal = traffic_gen mode; attack = argv for the attack script (None = none).
SCENARIOS = {
    "S0": {"normal": "idle",    "attack": None,  "label": "normal"},
    "S1": {"normal": "pingall", "attack": None,  "label": "normal"},
    "S2": {"normal": "iperf",   "attack": None,  "label": "normal"},
    "S3": {"normal": "mixed",   "attack": None,  "label": "normal"},
    "S4": {"normal": "mixed", "label": "flood",
           "attack": ["flood.py", "--rate", "80"]},
    "S5": {"normal": "mixed", "label": "slow_exhaustion",
           "attack": ["flood.py", "--rate", "8"]},
    "S6": {"normal": "mixed", "label": "flood",
           "attack": ["flood.py", "--rate", "80", "--on", "2", "--off", "6"]},
    "S7": {"normal": "mixed", "label": "spoofing",
           "attack": ["spoof.py", "--rate", "2"]},
}


def log(msg):
    print("%s  %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def h1_pid():
    out = subprocess.run(["pgrep", "-f", "mininet:h1$"],
                         capture_output=True, text=True).stdout.split()
    if not out:
        sys.exit("h1 not found. Is topo/lab_topo.py running?")
    return out[0]


def start_normal(mode, seconds, seed):
    """Background normal traffic for the whole run."""
    cmd = ["python3", os.path.join(HERE, "traffic_gen.py"),
           "--mode", mode, "--duration", str(seconds)]
    if seed is not None:
        cmd += ["--seed", str(seed)]
    return subprocess.Popen(cmd)


def run_attack(attack_argv, seconds):
    """Launch the attack inside h1 and wait for it to finish. Returns
    (t_start, t_end) as epoch seconds."""
    script = os.path.join(ATTACK_DIR, attack_argv[0])
    cmd = (["mnexec", "-a", h1_pid(), "python3", script]
           + attack_argv[1:] + ["--duration", str(seconds)])
    t_start = time.time()
    proc = subprocess.Popen(cmd)
    try:
        proc.wait(timeout=seconds + 30)
    except subprocess.TimeoutExpired:
        proc.terminate()
    return t_start, time.time()


def append_label(run_id, scenario, label, attacker, t_start, t_end):
    os.makedirs(os.path.dirname(LABELS), exist_ok=True)
    line = {"run_id": run_id, "scenario": scenario, "label": label,
            "attacker": attacker, "t_start": round(t_start, 3),
            "t_end": round(t_end, 3)}
    with open(LABELS, "a") as f:
        f.write(json.dumps(line) + "\n")
    log("labels.jsonl += %s" % json.dumps(line))


def main():
    p = argparse.ArgumentParser(description="Sentinel scenario runner")
    p.add_argument("scenario", choices=SCENARIOS)
    p.add_argument("--normal", type=int, default=60, help="normal phase seconds")
    p.add_argument("--attack", type=int, default=60, help="attack phase seconds")
    p.add_argument("--recovery", type=int, default=60,
                   help="recovery phase seconds")
    p.add_argument("--duration", type=int, default=900,
                   help="normal-only run length (S0..S3), default 900")
    p.add_argument("--seed", type=int, default=None)
    args = p.parse_args()

    spec = SCENARIOS[args.scenario]
    run_id = "%s_%s" % (args.scenario, time.strftime("%Y%m%d_%H%M%S"))
    log("run_id=%s scenario=%s" % (run_id, args.scenario))

    if spec["attack"] is None:
        # Normal-only run: traffic for --duration, labelled normal throughout.
        t_start = time.time()
        normal = start_normal(spec["normal"], args.duration, args.seed)
        log("normal (%s) for %ds" % (spec["normal"], args.duration))
        normal.wait()
        append_label(run_id, args.scenario, "normal", None,
                     t_start, time.time())
    else:
        total = args.normal + args.attack + args.recovery
        normal = start_normal(spec["normal"], total, args.seed)
        log("normal (%s) for %ds (whole run)" % (spec["normal"], total))

        log("phase 1: normal, %ds" % args.normal)
        time.sleep(args.normal)

        log("phase 2: attack %s, %ds" % (spec["attack"][0], args.attack))
        t_start, t_end = run_attack(spec["attack"], args.attack)

        log("phase 3: recovery, %ds" % args.recovery)
        time.sleep(args.recovery)

        normal.wait()
        append_label(run_id, args.scenario, spec["label"], ATTACKER,
                     t_start, t_end)

    log("run complete")


if __name__ == "__main__":
    main()
