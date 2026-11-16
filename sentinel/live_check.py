#!/usr/bin/env python3
"""Live check of the mitigation engine against the real ONOS + Mininet lab.
Run from the repo root: ./start-mitigation.sh live-check
Starts the topology itself (so stop any other Mininet first), runs every
'Expected results' row from the plan, then cleans everything up."""
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from functools import partial

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
S1, S2, S3 = ("of:%016x" % i for i in (1, 2, 3))
ENGINE = "http://127.0.0.1:9202"
AUDIT = "logs/audit.jsonl"
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def post(path, body):
    req = urllib.request.Request(ENGINE + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


def alert(sw, port, typ="flood", conf=0.9, **more):
    return post("/mitigate", {"switch": sw, "port": str(port), "type": typ, "score": 1.0, "confidence": conf,
                              "ts": time.time(), **more})


def ofctl(*args):
    return subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", *args], capture_output=True, text=True).stdout


def sentinel_flows(sw):
    return [l for l in ofctl("dump-flows", sw).splitlines() if re.search(r"priority=(49000|50000|51000)\b", l)]


def onos(path):
    req = urllib.request.Request("http://127.0.0.1:8181/onos/v1" + path,
                                 headers={"Authorization": "Basic b25vczpyb2Nrcw=="})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


def start_engine(dry=False):
    env = ["env", "GRAFANA_URL="] + (["DRY_RUN=1"] if dry else [])
    log = open("logs/live_check_engine.log", "a")
    user = os.environ.get("SUDO_USER", "mininet")  # run the engine as the real user, with our own Python
    p = subprocess.Popen(["sudo", "-u", user, *env, sys.executable, "sentinel/engine.py"],
                         stdout=log, stderr=log, start_new_session=True)  # else sudo won't relay our SIGINT
    for _ in range(50):
        try:
            urllib.request.urlopen(ENGINE + "/status", timeout=1)
            return p
        except Exception:
            time.sleep(0.2)
    raise SystemExit("engine did not start, see logs/live_check_engine.log")


def stop_engine(p):
    p.send_signal(signal.SIGINT)  # sudo forwards it, the engine releases its rules
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        print("engine ignored SIGINT, killing it", flush=True)
        subprocess.run(["pkill", "-9", "-f", "sentinel/engine.py"])


def wait_for(fn, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if fn():
            return time.time() - t0
        time.sleep(0.1)
    return None


def ping_loss(src, dst, count=10, interval=0.2):
    out = src.cmd(f"ping -c {count} -i {interval} -W 1 {dst.IP()}")
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    return float(m.group(1)) if m else 100.0


def main():
    setLogLevel("warning")
    subprocess.run(["mn", "-c"], capture_output=True)
    spec = importlib.util.spec_from_file_location("lab_topo", "topo/lab_topo.py")
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    net = Mininet(topo=lab.Lab1Topo(link_s3=True),
                  switch=partial(OVSSwitch, datapath="user", protocols="OpenFlow13"),
                  controller=partial(RemoteController, ip="127.0.0.1", port=6653), autoSetMacs=False)
    net.start()
    h1, h2, h3, h6 = (net.get(h) for h in ("h1", "h2", "h3", "h6"))
    engine = None
    try:
        wait_for(lambda: len(onos("/devices")["devices"]) >= 3 and len(onos("/links")["links"]) >= 4, 30)
        net.pingAll(timeout=1)
        loss = net.pingAll(timeout=1)
        check("pingall before Sentinel", loss == 0, f"{loss}% dropped")
        wait_for(lambda: len(onos("/hosts")["hosts"]) >= 6, 15)

        engine = start_engine()

        # 1. Rule installed fast + meter really drops
        t0 = time.time()
        r = alert(S1, 1)
        dt = wait_for(lambda: re.search(r"meter[=:]\d", ofctl("dump-meters", "s1")) and sentinel_flows("s1"), 5)
        check("flood -> meter + metered flow", r["action"] == "meter" and len(r["rule_ids"]) == 2, str(r))
        check("meter and flow visible in OVS within 2 s", dt is not None and dt <= 2, f"{dt and round(dt, 2)} s")
        loss = ping_loss(h1, h2, count=20, interval=0.1)
        stats = ofctl("meter-stats", "s1")
        band = [int(x) for x in re.findall(r"\bpacket_count[:=](\d+)", stats)]  # band counter, not packet_in_count
        check("meter drops traffic (band count > 0)", bool(band) and band[-1] > 0,
              f"band drops {band[-1] if band else '?'}, h1->h2 loss at 10 pkt/s {loss}%")

        # 2. Guardrails
        check("switch-to-switch port s1:3 refused", alert(S1, 3)["action"] == "refused:infra_port")
        check("duplicate on s1:1 refused", alert(S1, 1)["action"] == "refused:duplicate")

        # 3. Escalation to drop after 15 s while the detector keeps alerting; rules survive reconciliation
        for _ in range(16):
            alert(S1, 1)
            time.sleep(1)
        drop = [l for l in sentinel_flows("s1") if "priority=50000" in l]
        check("flood escalates to drop after 15 s", bool(drop) and "actions=drop" in drop[0], drop[0].strip() if drop else "no drop flow")
        check("Sentinel rules survive ONOS reconciliation (~16 s later)", len(sentinel_flows("s1")) == 2)

        # 4. Clean rollback
        r = post("/release", {"switch": S1, "port": "1"})
        gone = wait_for(lambda: not sentinel_flows("s1") and not re.search(r"meter[=:]\d", ofctl("dump-meters", "s1")), 5)
        check("release leaves no Sentinel flow or meter", r["action"] == "release:manual" and gone is not None)
        check("h1 reachable again after release", ping_loss(h1, h2) == 0)

        # 5. Spoofing: h3 (s1 port 2) takes h6's MAC, ONOS moves h6 to s1:2
        def spoof_and_wait():
            # Ping a different host each try: a pair already cached in the switch never reaches ONOS,
            # so ONOS would not notice the move (that is what broke a repeated spoof).
            h3.cmd("ip link set h3-eth0 address 00:00:00:00:00:06")
            targets = [net.get(h) for h in ("h2", "h1", "h4", "h5")]
            t0 = time.time()
            for i in range(20):
                h3.cmd(f"ping -c 1 -W 1 {targets[i % len(targets)].IP()}")
                if any(h["mac"] == "00:00:00:00:00:06" and
                       any(l["elementId"] == S1 and l["port"] == "2" for l in h["locations"])
                       for h in onos("/hosts")["hosts"]):
                    return time.time() - t0
                time.sleep(0.5)
            return None

        def unspoof_and_recover():
            h3.cmd("ip link set h3-eth0 address 00:00:00:00:00:03")
            for h in net.hosts:  # the impostor poisoned h2's ARP cache (h3's IP -> h6's MAC); a test artefact
                h.cmd("ip neigh flush all")
            return wait_for(lambda: ping_loss(h6, h2, count=2, interval=0.2) == 0, 15)

        def h6_blocked_on_s1_2():
            return any("dl_src=00:00:00:00:00:06" in l and "in_port=2" in l for l in sentinel_flows("s1"))

        check("spoof makes ONOS report h6 on s1:2", spoof_and_wait() is not None)
        r = alert(S1, 2, "spoofing")
        check("spoofing -> drop h6 MAC on s1:2 only", r["action"] == "drop_mac" and h6_blocked_on_s1_2(), str(r))
        check("impostor frames dropped", ping_loss(h3, h2, count=5) == 100)
        check("h1 unaffected during spoof block", ping_loss(h1, h2, count=5) == 0)
        post("/release", {"switch": S1, "port": "2"})
        recovered = unspoof_and_recover()
        check("h6 reachable again after release", recovered is not None, f"after {recovered and round(recovered, 1)} s")

        # 5b. Spoofing with no prior knowledge: the engine is restarted while h6 is already hijacked,
        # so the first place it ever sees h6 is the impostor port. Only the detector's victim_mac helps.
        stop_engine(engine)
        check("spoof again before the engine starts", spoof_and_wait() is not None)
        engine = start_engine()
        r = alert(S1, 2, "spoofing")
        check("no history, no victim_mac -> fallback meter+flag_human", r["action"] == "meter+flag_human", str(r))
        post("/release", {"switch": S1, "port": "2"})
        r = alert(S1, 2, "spoofing", victim_mac="00:00:00:00:00:01")
        check("victim_mac not on that port (h1) is ignored -> fallback", r["action"] == "meter+flag_human"
              and not any("dl_src=00:00:00:00:00:01" in l for l in sentinel_flows("s1")), str(r))
        post("/release", {"switch": S1, "port": "2"})
        r = alert(S1, 2, "spoofing", victim_mac="00:00:00:00:00:06")
        check("no history + victim_mac -> drop h6 MAC on s1:2", r["action"] == "drop_mac" and h6_blocked_on_s1_2(), str(r))
        check("impostor frames dropped (victim from detector)", ping_loss(h3, h2, count=5) == 100)
        post("/release", {"switch": S1, "port": "2"})
        recovered = unspoof_and_recover()
        check("h6 reachable again after release (victim from detector)", recovered is not None,
              f"after {recovered and round(recovered, 1)} s")

        # 6. Low confidence -> unknown playbook
        r = alert(S2, 1, "flood", conf=0.3)
        check("low confidence -> meter + flag_human", r["action"] == "meter+flag_human", str(r))
        post("/release", {"switch": S2, "port": "1"})

        # 7. Rate limit: fresh engine, 5 actions fine, 6th refused
        stop_engine(engine)
        engine = start_engine()
        ports = [(S1, 1), (S1, 2), (S2, 1), (S2, 2), (S3, 1)]
        acts = [alert(sw, p)["action"] for sw, p in ports]
        sixth = alert(S3, 2)["action"]
        check("5 actions allowed, 6th within a minute refused", acts == ["meter"] * 5 and sixth == "refused:rate_limit",
              f"{acts} then {sixth}")

        # 8. Ctrl-C on the engine releases everything
        stop_engine(engine)
        engine = None
        left = sum(len(sentinel_flows(s)) for s in ("s1", "s2", "s3"))
        check("engine shutdown releases every rule", left == 0, f"{left} Sentinel flows left")

        # 9. Dry run is harmless
        engine = start_engine(dry=True)
        r = alert(S1, 1)
        time.sleep(1.5)
        line = json.loads(open(AUDIT).read().splitlines()[-1])
        check("DRY_RUN: audit written, nothing installed",
              r["dry_run"] and not sentinel_flows("s1") and line["dry_run"] and line["port"] == "1")
        stop_engine(engine)
        engine = None

        check("pingall after everything", net.pingAll(timeout=1) == 0)
    finally:
        if engine:
            stop_engine(engine)
        net.stop()
        if os.path.exists(AUDIT):
            shutil.move(AUDIT, "logs/live_check_audit.jsonl")  # keep the real audit log clean
        subprocess.run(["chown", "-R", "mininet:mininet", "logs"])
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f", failed: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
