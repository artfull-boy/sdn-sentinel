#!/usr/bin/env python3
"""
Sentinel: normal (benign) traffic generator.

Runs OUTSIDE the Mininet CLI. The topology runs in one terminal, this script
in another. It enters each host's network namespace with `mnexec -a <pid>`,
which is exactly what happens when you type a command in `xterm h1`.

Modes:
  idle     no traffic at all (S0)
  pingall  every host pings every other host once, then waits (S1)
  iperf    TCP bulk transfers between random host pairs (S2)
  mixed    random pings and short transfers at random times (S3)

Usage (topology must already be running):
  sudo python3 scenarios/traffic_gen.py --mode pingall --duration 60
  sudo python3 scenarios/traffic_gen.py --mode mixed --duration 900 --seed 3
"""

import argparse
import itertools
import random
import subprocess
import sys
import time

# Same addressing as topo/lab_topo.py
HOSTS = {
    "h1": "10.0.1.1", "h3": "10.0.2.1",   # s1
    "h2": "10.0.1.2", "h4": "10.0.2.2",   # s2
    "h5": "10.0.3.1", "h6": "10.0.3.2",   # s3
}

QUIET = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
PIDS = {}          # host name -> PID of its Mininet shell
BACKGROUND = []    # long-running processes to stop at the end


def log(msg):
    print("%s  %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def find_host_pids():
    """Each Mininet host is a bash process started as 'bash ... mininet:h1'."""
    for name in HOSTS:
        out = subprocess.run(["pgrep", "-f", "mininet:%s$" % name],
                             capture_output=True, text=True).stdout.split()
        if not out:
            sys.exit("Host %s not found. Is topo/lab_topo.py running?" % name)
        PIDS[name] = out[0]


def in_host(host, cmd, background=False):
    """Run cmd inside host's network namespace."""
    full = ["mnexec", "-a", PIDS[host]] + cmd
    if background:
        proc = subprocess.Popen(full, **QUIET)
        BACKGROUND.append(proc)
        return proc
    return subprocess.run(full, **QUIET).returncode


def ping(src, dst, count=1):
    rc = in_host(src, ["ping", "-c", str(count), "-W", "1", HOSTS[dst]])
    return rc == 0


def random_pair():
    return random.sample(list(HOSTS), 2)


def start_iperf_servers():
    for h in HOSTS:
        in_host(h, ["iperf", "-s"], background=True)
    time.sleep(1)  # give the servers time to listen


# ---------------------------------------------------------------- modes

def mode_idle(end, args):
    log("idle until the end of the run")
    while time.time() < end:
        time.sleep(1)


def mode_pingall(end, args):
    while time.time() < end:
        pairs = list(itertools.permutations(HOSTS, 2))   # 30 ordered pairs
        ok = sum(ping(a, b) for a, b in pairs)
        log("pingall: %d/%d replies" % (ok, len(pairs)))
        time.sleep(args.period)


def mode_iperf(end, args):
    start_iperf_servers()
    while time.time() < end:
        src, dst = random_pair()
        secs = random.randint(5, 20)
        log("iperf %s -> %s for %d s" % (src, dst, secs))
        in_host(src, ["iperf", "-c", HOSTS[dst], "-t", str(secs)])
        time.sleep(random.uniform(2, 10))


def mode_mixed(end, args):
    start_iperf_servers()
    while time.time() < end:
        src, dst = random_pair()
        r = random.random()
        if r < 0.60:
            n = random.randint(1, 5)
            log("ping %s -> %s x%d" % (src, dst, n))
            ping(src, dst, n)
        elif r < 0.85:
            secs = random.randint(3, 8)
            log("short iperf %s -> %s for %d s (background)" % (src, dst, secs))
            in_host(src, ["iperf", "-c", HOSTS[dst], "-t", str(secs)],
                    background=True)
        else:
            log("quiet")
        time.sleep(random.uniform(0.5, 5))


MODES = {"idle": mode_idle, "pingall": mode_pingall,
         "iperf": mode_iperf, "mixed": mode_mixed}


def main():
    p = argparse.ArgumentParser(description="Sentinel normal traffic generator")
    p.add_argument("--mode", choices=MODES, required=True)
    p.add_argument("--duration", type=int, default=60, help="seconds")
    p.add_argument("--period", type=int, default=15,
                   help="pingall: seconds between rounds (default 15)")
    p.add_argument("--seed", type=int, default=None,
                   help="random seed, so a run can be repeated exactly")
    args = p.parse_args()

    random.seed(args.seed)
    find_host_pids()
    log("mode=%s duration=%ds seed=%s" % (args.mode, args.duration, args.seed))

    end = time.time() + args.duration
    try:
        MODES[args.mode](end, args)
    except KeyboardInterrupt:
        log("interrupted")
    finally:
        for proc in BACKGROUND:
            proc.terminate()
        log("done")


if __name__ == "__main__":
    main()
