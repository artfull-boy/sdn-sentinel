#!/usr/bin/env python3
"""Live check of the mitigation engine against the real ONOS + Mininet lab.
Run from the repo root: ./start-mitigation.sh live-check
Starts the topology itself (so stop any other Mininet first), runs every
'Expected results' row from the plan, then cleans everything up."""
import importlib.util
import itertools
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
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


def get(path, base=ENGINE):
    return urllib.request.urlopen(base + path, timeout=5).read().decode()


def release_button(sw, port, origin):
    """What the Release button on the engine's page sends. Returns the HTTP status."""
    body = urllib.parse.urlencode({"switch": sw, "port": str(port)}).encode()
    req = urllib.request.Request(ENGINE + "/release", body, {"Origin": origin})
    try:
        return urllib.request.urlopen(req, timeout=5).status
    except urllib.error.HTTPError as e:
        return e.code


def active():
    return set(json.loads(get("/status")))


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


# A flood with a new random source MAC on every packet (like scenarios/attacks/flood.py), written
# with a raw socket so it needs no scapy. Runs inside a Mininet host: <iface> <dst_mac> <dst_ip> <pps> <s>
RAW_FLOOD = r'''
import os, random, socket, struct, sys, time
iface, dst_mac, dst_ip, pps, secs = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
def csum(b):
    b += b"\0" * (len(b) % 2)
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff
src_ip = socket.inet_aton(os.popen("ip -4 -o addr show " + iface).read().split()[3].split("/")[0])
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); sock.bind((iface, 0))
end, n = time.time() + secs, 0
while time.time() < end:
    src = bytes([0x02] + [random.randrange(256) for _ in range(5)])
    icmp = struct.pack("!BBHHH", 8, 0, 0, n & 0xffff, 1) + b"sentinel"
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), n & 0xffff, 0, 64, 1, 0, src_ip, socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    sock.send(bytes.fromhex(dst_mac.replace(":", "")) + src + b"\x08\x00" + ip + icmp)
    n += 1
    time.sleep(1 / pps)
'''


def fake_mac_flood(host, dst, pps, secs):
    """Start a random-source-MAC flood from a Mininet host; returns the process."""
    return host.popen([sys.executable, "-c", RAW_FLOOD, host.defaultIntf().name, dst.MAC(), dst.IP(),
                       str(pps), str(secs)])


def audit_actions(port_key, since=0):
    lines = [json.loads(l) for l in open(AUDIT)][since:]
    return [a["action"] for a in lines if (a["switch"], a["port"]) == port_key]


def audit_len():
    return sum(1 for _ in open(AUDIT)) if os.path.exists(AUDIT) else 0


def ping_loss(src, dst, count=10, interval=0.2):
    out = src.cmd(f"ping -c {count} -i {interval} -W 1 {dst.IP()}")
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    return float(m.group(1)) if m else 100.0


def main():
    setLogLevel("warning")
    try:
        onos("/devices")
    except Exception:
        raise SystemExit("ONOS is not reachable on 127.0.0.1:8181. Start it first: "
                         "docker compose up -d   (or: docker start onos), wait ~1 min, then retry.")
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
        # Attack traffic from h1 during sections 1-3 (50 pkt/s = 300 per 6 s, above FLOOD_BLOCK_PKTS),
        # so the engine keeps blocking while these checks run. Stopped before section 4.
        h1.cmd(f"ping -i 0.02 {net.get('h4').IP()} > /dev/null 2>&1 &")
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
        h1.cmd("pkill -f 'ping -i 0.02'")
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

        h6_targets = itertools.cycle([net.get(h) for h in ("h5", "h1", "h4", "h2")])

        def h6_talks_and_is_home():
            # A different peer each time, so the packet is not switched from cache and reaches ONOS
            h6.cmd(f"ping -c 1 -W 1 {next(h6_targets).IP()}")
            return any(h["mac"] == "00:00:00:00:00:06" and
                       any(l["elementId"] == S3 and l["port"] == "2" for l in h["locations"])
                       for h in onos("/hosts")["hosts"])

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
        r = alert(S1, 2, "spoofing", victim_mac="00:00:00:00:00:99")
        check("victim_mac seen nowhere is ignored -> fallback", r["action"] == "meter+flag_human"
              and not any("dl_src=00:00:00:00:00:99" in l for l in sentinel_flows("s1")), str(r))
        post("/release", {"switch": S1, "port": "2"})
        r = alert(S1, 2, "spoofing", victim_mac="00:00:00:00:00:06")
        check("no history + victim_mac -> drop h6 MAC on s1:2", r["action"] == "drop_mac" and h6_blocked_on_s1_2(), str(r))
        check("impostor frames dropped (victim from detector)", ping_loss(h3, h2, count=5) == 100)
        post("/release", {"switch": S1, "port": "2"})
        recovered = unspoof_and_recover()
        check("h6 reachable again after release (victim from detector)", recovered is not None,
              f"after {recovered and round(recovered, 1)} s")

        # 5c. Detector says "unknown" first, then "spoofing" + victim_mac, while ONOS has already
        # flipped h6 back to its real port (the victim keeps talking). Fresh engine: h6 learnt at home.
        stop_engine(engine)
        engine = start_engine()
        check("spoof h6 again", spoof_and_wait() is not None)
        h6_home = wait_for(lambda: h6_talks_and_is_home(), 20)
        check("ONOS flips h6 back to s3:2 while h3 impersonates it", h6_home is not None)
        r = alert(S1, 2, "unknown")
        metrics = get("/metrics")
        check("unknown first -> meter + flag_human, flagged in /metrics", r["action"] == "meter+flag_human"
              and f'sentinel_flag_human{{switch="{S1}",port="2"}} 1' in metrics
              and 'type="unknown",action="meter+flag_human"' in metrics, str(r))
        r = alert(S1, 2, "spoofing", victim_mac="00:00:00:00:00:06")
        meter_left = [l for l in sentinel_flows("s1") if "priority=49000" in l and "in_port=2" in l]
        check("then spoofing + victim_mac -> upgraded to drop h6 MAC, meter removed",
              r["action"] == "drop_mac" and h6_blocked_on_s1_2() and not meter_left, str(r))
        check("impostor frames dropped after upgrade", ping_loss(h3, h2, count=5) == 100)
        check("h6 reachable during the block", ping_loss(h6, h2, count=5) == 0)
        post("/release", {"switch": S1, "port": "2"})
        recovered = unspoof_and_recover()
        check("h6 reachable after release (upgrade case)", recovered is not None)

        # 5d. unknown -> flood upgrade leaves exactly one meter and one metered flow
        alert(S2, 1, "unknown")
        r = alert(S2, 1, "flood")
        meters = re.findall(r"meter[=:]\d", ofctl("dump-meters", "s2"))
        flows = [l for l in sentinel_flows("s2") if "in_port=1" in l]
        check("unknown then flood -> upgraded to the flood meter", r["action"] == "meter"
              and len(meters) == 1 and len(flows) == 1, f"{r} meters={len(meters)} flows={len(flows)}")
        post("/release", {"switch": S2, "port": "1"})

        # 5e. Flood release from measurements, no timer (BLOCK <-> SAMPLE), with real fake-MAC floods
        #     from h5 (s3 port 1): fast flood -> blocked; slow flood -> sampled, fake MACs seen ->
        #     blocked again; attack over -> sampled, no new hosts -> released.
        h5 = net.get("h5")
        k31, n0 = (S3, "1"), audit_len()
        fast = fake_mac_flood(h5, h2, 80, 60)
        alert(S3, 1, "flood")
        for _ in range(16):  # the detector keeps reporting the port for 16 s
            alert(S3, 1, "flood")
            time.sleep(1)
        time.sleep(25)
        st = json.loads(get("/status")).get(f"{S3} 1", {})
        check("fast fake-MAC flood (80 pkt/s): meter, then drop after 15 s, still blocked 40 s in",
              st.get("action") == "drop" and st.get("phase") == "block" and (st.get("measured") or 0) > 200,
              f"{st.get('action')}/{st.get('phase')}, {st.get('measured')} dropped packets per 6 s")
        fast.kill()
        slow = fake_mac_flood(h5, h2, 8, 60)
        cycled = wait_for(lambda: "reblock" in audit_actions(k31, n0), 45)
        acts = audit_actions(k31, n0)
        check("slow fake-MAC flood (8 pkt/s): sampled, new hosts seen -> drop rule again",
              cycled is not None and "sample" in acts, f"{acts}")
        slow.kill()
        released = wait_for(lambda: f"{S3} 1" not in active(), 60)
        last = [json.loads(l) for l in open(AUDIT)][-1]
        check("attack over: sampled, no new hosts twice -> released, no rules left", released is not None
              and last["action"] == "release:auto" and not [l for l in sentinel_flows("s3") if "in_port=1" in l],
              f"after {released and round(released)} s, {last.get('new_hosts_per_check')} new hosts per check")
        check("h5 reachable after the release", ping_loss(h5, h2, count=5) == 0)

        # 5f. Spoofing release from the MAC-drop rule's counter: kept while spoofed frames arrive
        check("spoof h6 again for the counter test", spoof_and_wait() is not None)
        r = alert(S1, 2, "spoofing")
        h3.cmd(f"ping -i 0.2 {h2.IP()} > /dev/null 2>&1 &")  # h3 keeps sending as h6: every frame hits the rule
        time.sleep(30)
        st = json.loads(get("/status")).get(f"{S1} 2", {})
        check("spoofed frames still arriving -> MAC block kept after 30 s", r["action"] == "drop_mac"
              and st.get("phase") == "spoof" and (st.get("measured") or 0) > 0,
              f"{st.get('measured')} spoofed frames per 6 s")
        h3.cmd("pkill -f 'ping -i 0.2'")
        released = wait_for(lambda: f"{S1} 2" not in active(), 40)
        check("no more spoofed frames (2 checks) -> released", released is not None,
              f"after {released and round(released)} s")
        recovered = unspoof_and_recover()
        check("h6 reachable after the spoofing release", recovered is not None)

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

        # 7b. Operator page and Release button (what the Grafana link opens)
        page = get("/release")
        check("release page lists the 5 active mitigations", page.count("Release</button>") == 5)
        check("Release from another website refused", release_button(S1, 1, "http://evil.example") == 403
              and f"{S1} 1" in active())
        code = release_button(S1, 1, "http://localhost:9202")
        gone = wait_for(lambda: not [l for l in sentinel_flows("s1") if "in_port=1" in l], 5)
        check("Release button removes the mitigation and its rules", code == 200
              and f"{S1} 1" not in active() and gone is not None)

        # 7c. The API listens on 127.0.0.1 only
        ip = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()[0]
        try:
            get("/status", base=f"http://{ip}:9202")
            reachable = True
        except Exception:
            reachable = False
        check(f"engine not reachable from the network ({ip}:9202)", not reachable)

        # 8. Ctrl-C on the engine releases everything
        stop_engine(engine)
        engine = None
        left = sum(len(sentinel_flows(s)) for s in ("s1", "s2", "s3"))
        check("engine shutdown releases every rule", left == 0, f"{left} Sentinel flows left")

        # 8b. /pin keeps a real mitigation past its automatic release, /release then removes it
        engine = start_engine()
        alert(S3, 1, "flood")
        r = post("/pin", {"switch": S3, "port": "1"})
        check("pin a flood on s3:1", r["action"] == "pin" and 'pinned="1"' in get("/metrics"), str(r))
        time.sleep(35)  # a flood is normally released after 30 s calm
        rules = [l for l in sentinel_flows("s3") if "in_port=1" in l]
        check("pinned flood still active after 35 s, rules still in the switch",
              f"{S3} 1" in active() and len(rules) == 1, f"{len(rules)} flows")
        r = post("/release", {"switch": S3, "port": "1"})
        gone = wait_for(lambda: not [l for l in sentinel_flows("s3") if "in_port=1" in l], 5)
        check("release of the pinned port removes its rules", r["action"] == "release:manual" and gone is not None)
        r1, r2 = post("/pin", {"switch": S3, "port": "1"}), post("/release", {"switch": S3, "port": "1"})
        check("pin and release on an inactive port -> refused:not_active",
              r1["action"] == r2["action"] == "refused:not_active", f"{r1['action']}, {r2['action']}")
        stop_engine(engine)
        engine = None

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
