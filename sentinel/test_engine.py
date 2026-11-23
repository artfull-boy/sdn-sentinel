"""Offline check of playbooks, guardrails, the measurement-based release and the HTTP API,
with a fake ONOS (simulated time, switch counters and host list).
Run: ./start-mitigation.sh test   (or: python3 sentinel/test_engine.py)"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import engine  # noqa: E402

onos = engine.onos  # patch the module object the engine really uses
SW = "of:0000000000000001"
H1, H3, H6 = "00:00:00:00:00:01", "00:00:00:00:00:03", "00:00:00:00:00:06"
LIVE, counter = set(), iter(range(100, 10**6))
HOSTS = [(H1, (SW, "1")), (H6, (SW, "6")), (H3, (SW, "2"))]  # h1 on port 1, h3 on port 2, h6 on port 6


def fake(kind):
    def make(*args):
        rid = str(next(counter))
        LIVE.add(f"{kind}:{rid}")
        return rid
    return make


onos.infra_ports = lambda: {(SW, "3")}  # s1 port 3 goes to another switch
onos.hosts = lambda: list(HOSTS)
onos.add_meter = fake("meter")
onos.meter_port = onos.drop_port = onos.drop_mac = fake("flow")
onos.delete_flow = lambda sw, rid: LIVE.discard(f"flow:{rid}")
onos.delete_meter = lambda sw, rid: LIVE.discard(f"meter:{rid}")
PURGED = []
onos.purge_mac_flows = PURGED.append
engine.AUDIT = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
engine.GRAFANA = ""

# Simulated time and switch: counters per flow rule, copied by "ONOS" every 5 s, like the real one
CLOCK = [1_000_000.0]
COUNTS, SNAP, SNAP_AT = {}, {}, [CLOCK[0]]
fake_macs = iter(range(1, 10**6))
engine.clock = lambda: CLOCK[0]
BORN = {}  # flow id -> creation time


def fake_flow(*args):
    rid = fake("flow")(*args)
    BORN[rid] = CLOCK[0]
    return rid


def flow_packets(sw, fid):
    # Like real ONOS: a new rule's counter is only reported after a later poll; until then 0,
    # "refreshed" at its creation time (seen live right after the flood escalation)
    if fid not in SNAP:
        return 0, BORN.get(fid, SNAP_AT[0])
    return SNAP[fid], SNAP_AT[0]


onos.meter_port = onos.drop_port = onos.drop_mac = fake_flow
onos.flow_packets = flow_packets


def run(seconds, traffic=None, fake_mac_rate=None, hot=False):
    """Advance time 1 s at a time. traffic = {port: packets/s sent on that port}; fake_mac_rate =
    {port: packets/s of them with a new random MAC}; hot = the detector keeps reporting those ports."""
    for _ in range(int(seconds)):
        CLOCK[0] += 1
        for port, pps in (traffic or {}).items():
            m = engine.ACTIVE.get((SW, port))
            if m and any(r.startswith("flow:") for r in m["rules"]):
                fid = [r.split(":", 1)[1] for r in m["rules"] if r.startswith("flow:")][-1]  # highest priority
                COUNTS[fid] = COUNTS.get(fid, 0) + pps
        for port, rate in (fake_mac_rate or {}).items():
            m = engine.ACTIVE.get((SW, port))
            # Only packets that reach ONOS create hosts: none while blocked, at most the meter's
            # rate while sampling, all of them when the port has no rule.
            visible = rate if not m else (min(rate, engine.FLOOD_SAMPLE_PPS) if m["phase"] == "sample" else 0)
            for _ in range(int(visible)):
                n = next(fake_macs)
                HOSTS.append((f"02:00:00:{n >> 16 & 255:02x}:{n >> 8 & 255:02x}:{n & 255:02x}", (SW, port)))
        if CLOCK[0] - SNAP_AT[0] >= 5:
            SNAP.clear()
            SNAP.update({f: c for f, c in COUNTS.items() if CLOCK[0] - BORN.get(f, 0) >= 6})  # new rules: a poll later
            SNAP_AT[0] = CLOCK[0]
        engine.tick(now=CLOCK[0], hot={(SW, p) for p in (traffic or {})} if hot else set())


def alert(port, typ="flood", conf=0.9, **more):
    return engine.mitigate({"switch": SW, "port": port, "type": typ, "score": 1.0, "confidence": conf,
                            "ts": time.time(), **more})


def release(port):
    return engine.release({"switch": SW, "port": port})


def audit_lines():
    return [json.loads(line) for line in open(engine.AUDIT)]


def last_audit():
    return audit_lines()[-1]


def actions_since(n, port):
    return [a["action"] for a in audit_lines()[n:] if a["port"] == port and not a["action"].startswith("refused")]


def new_minute():  # forget earlier actions so the 5 per minute guardrail doesn't interfere
    engine.ACTIONS = engine.deque()


engine.learn_hosts()

# Guardrail: switch-to-switch port is refused
assert alert("3")["action"] == "refused:infra_port"

# The link map is cached (no ONOS call on the alert path). With ONOS down, a fresh cache still
# protects switch links; once the cache is too old, new mitigations are refused (fail closed).
calls = []


def onos_down():
    calls.append(1)
    raise OSError("ONOS down")


real_infra, onos.infra_ports = onos.infra_ports, onos_down
assert alert("3")["action"] == "refused:infra_port" and not calls
engine.INFRA["at"] -= engine.INFRA_MAX_AGE_S + 1
assert alert("14")["action"] == "refused:onos_unreachable" and calls and (SW, "14") not in engine.ACTIVE
onos.infra_ports = real_infra
engine.refresh_infra()

# ---- Flood: meter at the alert, drop after 15 s, then the BLOCK <-> SAMPLE cycle, no timer -------
n0 = len(audit_lines())
r = alert("1")
m1 = engine.ACTIVE[(SW, "1")]
assert r["action"] == "meter" and len(r["rule_ids"]) == 2 and m1["phase"] == "block", r
assert alert("1")["action"] == "refused:duplicate"
run(16, {"1": 80}, {"1": 80}, hot=True)               # 80 pkt/s, a new fake MAC on each packet
assert m1["action"] == "drop" and len(m1["rules"]) == 3, m1  # escalated after 15 s
run(120, {"1": 80}, {"1": 80})                         # a long attack: 480 packets per 6 s > 200
assert m1["phase"] == "block" and m1["measured"] == 480, m1["measured"]
# (no false SAMPLE right after the escalation, when ONOS has not reported the new drop rule yet)
assert "sample" not in actions_since(n0, "1"), actions_since(n0, "1")
# The attacker slows down to 8 pkt/s (48 per 6 s <= 200): SAMPLE, where its fake MACs show up
# (up to 8 x 3 = 24 per check > 5), twice in a row -> back to the drop rule
run(40, {"1": 8}, {"1": 8})
acts = actions_since(n0, "1")
assert acts[:2] == ["meter", "drop"] and "sample" in acts and "reblock" in acts, acts
reblock = [a for a in audit_lines() if a["action"] == "reblock"][0]
assert reblock["new_hosts_per_check"] > engine.FLOOD_NEW_HOSTS, reblock
# The attack stops; h1 keeps normal traffic (5 pkt/s, its own MAC only): SAMPLE, no new hosts
# three times in a row -> released, no rules left
run(30, {"1": 5})
assert (SW, "1") not in engine.ACTIVE and not LIVE, (engine.ACTIVE.get((SW, "1")), LIVE)
line = last_audit()
assert line["action"] == "release:auto" and line["new_hosts_per_check"] <= engine.FLOOD_NEW_HOSTS, line

# A counter that goes down (rule reinstalled, switch restarted) is only a new baseline: no decision
new_minute()
alert("9")
m9 = engine.ACTIVE[(SW, "9")]
run(12, {"9": 80})
for fid in list(COUNTS):
    COUNTS[fid] = SNAP[fid] = 0
run(6, {"9": 80})
assert m9["phase"] == "block", m9["phase"]
release("9")

# Slow flood (S5): meter only (no escalation). 8 pkt/s is under the packet threshold, so it is
# sampled at once, and its fake MACs put the drop rule in place
new_minute()
n0 = len(audit_lines())
assert alert("5", "slow_exhaustion")["action"] == "meter"
run(30, {"5": 8}, {"5": 8})
acts = actions_since(n0, "5")
assert acts[0] == "meter" and "sample" in acts and "reblock" in acts, acts
run(40)  # attack over
assert (SW, "5") not in engine.ACTIVE and not LIVE, acts

# ---- Spoofing: the MAC-drop rule's counter; any spoofed frame keeps the block --------------------
HOSTS[:] = [h for h in HOSTS if not h[0].startswith("02:")] + [(H6, (SW, "2"))]  # h6 now seen on port 2
HOSTS.remove((H6, (SW, "6")))
new_minute()
r = alert("2", "spoofing")
assert r["action"] == "drop_mac" and r["rule_ids"][1] == "mac:" + H6, r
run(60, {"2": 0.5})  # one spoofed frame every 2 s for a minute: kept
assert (SW, "2") in engine.ACTIVE and engine.ACTIVE[(SW, "2")]["measured"] > 0
run(25)              # no spoofed frame for 2 checks in a row: released, stale fwd flows purged
assert (SW, "2") not in engine.ACTIVE and PURGED == [H6], PURGED
assert last_audit()["action"] == "release:auto" and last_audit()["spoofed_per_check"] == 0

# Low confidence becomes unknown: meter + flag, only a person releases it
new_minute()
assert alert("4", conf=0.3)["action"] == "meter+flag_human"
run(120)
assert (SW, "4") in engine.ACTIVE and engine.ACTIVE[(SW, "4")]["phase"] is None

# Upgrade unknown -> flood: the unknown meter is replaced by the flood playbook, which then runs normally
old = set(engine.ACTIVE[(SW, "4")]["rules"])
r = alert("4", "flood")
assert r["action"] == "meter" and last_audit()["upgraded_from"] == "unknown", r
assert engine.ACTIVE[(SW, "4")]["phase"] == "block" and not (old & LIVE) and LIVE == set(r["rule_ids"])
run(16, {"4": 80}, hot=True)
assert engine.ACTIVE[(SW, "4")]["action"] == "drop"
release("4")

# Upgrade unknown -> spoofing: the meter goes, the MAC block comes (detector says unknown first)
new_minute()
assert alert("2", "unknown")["action"] == "meter+flag_human"
r = alert("2", "spoofing")
assert r["action"] == "drop_mac" and LIVE == {r["rule_ids"][0]}, (r, LIVE)
release("2")

# ONOS flipped h6 back home: no victim on port 2 right now, so the upgrade is refused (stays metered)...
HOSTS[:] = [(H6, (SW, "6")) if h[0] == H6 else h for h in HOSTS]
new_minute()
assert alert("2", "unknown")["action"] == "meter+flag_human"
assert alert("2", "spoofing")["action"] == "refused:duplicate" and engine.ACTIVE[(SW, "2")]["type"] == "unknown"
# ...but the detector's victim_mac is accepted because h6's home is another port
r = alert("2", "spoofing", victim_mac=H6)
assert r["action"] == "drop_mac" and r["rule_ids"][1] == "mac:" + H6, r
release("2")

# victim_mac naming a MAC seen nowhere (not on this port, no home) is refused: fallback to unknown
new_minute()
assert alert("2", "spoofing", victim_mac="00:00:00:00:00:99")["action"] == "meter+flag_human"
release("2")

# No prior knowledge: the engine first sees h6 already on the impostor port
engine.HOME.clear()
HOSTS[:] = [(H6, (SW, "2")), (H3, (SW, "2"))]
engine.learn_hosts()
assert alert("2", "spoofing")["action"] == "meter+flag_human"            # no history, no hint: fallback
release("2")
assert alert("2", "spoofing", victim_mac="00:00:00:00:00:01")["action"] == "meter+flag_human"  # unknown MAC
release("2")
r = alert("2", "spoofing", victim_mac=H6.lower())                         # the detector names h6
assert r["action"] == "drop_mac" and r["rule_ids"][1] == "mac:" + H6, r
assert last_audit()["victim_mac"] == H6.lower()
del PURGED[:]
release("2")
assert PURGED == [H6] and not engine.ACTIVE and not LIVE, (PURGED, LIVE)

# Pin: no automatic change at all (no sampling, no release), even with no traffic
new_minute()
alert("5")
engine.pin({"switch": SW, "port": "5"})
run(60)
assert (SW, "5") in engine.ACTIVE and engine.ACTIVE[(SW, "5")]["action"] == "meter"
release("5")

# Rate limit: 5 new mitigations in a minute are fine, the 6th is refused
new_minute()
assert [alert(p)["action"] for p in ("7", "8", "10", "11", "12")] == ["meter"] * 5
assert alert("13")["action"] == "refused:rate_limit"
for p in ("7", "8", "10", "11", "12"):
    assert release(p)["action"] == "release:manual"
assert not engine.ACTIVE and not LIVE, LIVE

# Metrics for Grafana: an unknown mitigation shows up as flagged, with an info row
new_minute()
alert("4", conf=0.3)
text = engine.metrics()
assert f'sentinel_flag_human{{switch="{SW}",port="4"}} 1' in text
assert (f'sentinel_mitigation_info{{switch="{SW}",port="4",type="unknown",action="meter+flag_human",'
        f'phase="manual",pinned="0",flag_human="1"}} 1') in text
assert f'sentinel_mitigation_active{{switch="{SW}",port="4"}} 1' in text

# HTTP API: release page, origin check, form and JSON posts
srv = ThreadingHTTPServer(("127.0.0.1", 0), engine.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_address[1]}"


def http(path, data=None, headers=None):
    req = urllib.request.Request(base + path, data, headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def form_post(origin):
    body = urllib.parse.urlencode({"switch": SW, "port": "4"}).encode()
    return http("/release", body, {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"})


code, page = http("/release")
assert code == 200 and "Release</button>" in page and "meter+flag_human" in page and "manual release" in page
code, page = http("/release?" + urllib.parse.urlencode({"switch": SW, "port": "4"}))
assert code == 200 and "unknown" in page
code, page = http("/release?" + urllib.parse.urlencode({"switch": "<script>x</script>", "port": "1"}))
assert "<script>" not in page and "&lt;script&gt;" in page
assert form_post("http://evil.example")[0] == 403 and (SW, "4") in engine.ACTIVE
code, page = form_post("http://localhost:3000")
assert code == 200 and "release:manual" in page and (SW, "4") not in engine.ACTIVE
new_minute()
code, body = http("/mitigate", json.dumps({"switch": SW, "port": "4", "type": "flood", "confidence": 0.9}).encode(),
                  {"Content-Type": "application/json"})
assert code == 200 and json.loads(body)["action"] == "meter"
port4 = json.dumps({"switch": SW, "port": "4"}).encode()
code, body = http("/pin", port4)
assert code == 200 and json.loads(body)["action"] == "pin" and engine.ACTIVE[(SW, "4")]["pinned"], body
assert 'pinned="1"' in http("/metrics")[1]
run(60)  # no traffic at all, but a pinned port is never changed or released automatically
assert (SW, "4") in engine.ACTIVE
status = json.loads(http("/status")[1])[f"{SW} 4"]
assert status["phase"] == "block" and "known_macs" not in status and "last_count" not in status, status
code, body = http("/release", port4)
assert code == 200 and json.loads(body)["action"] == "release:manual" and (SW, "4") not in engine.ACTIVE
assert json.loads(http("/pin", port4)[1])["action"] == "refused:not_active"      # nothing to pin
assert json.loads(http("/release", port4)[1])["action"] == "refused:not_active"  # nothing to release
assert http("/mitigate", b"not json")[0] == 400
assert http("/mitigate", b'{"port": "4"}')[0] == 400
assert http("/nope")[0] == 404
code, text = http("/metrics")
assert code == 200 and "# TYPE sentinel_mitigation_measured gauge" in text
code, body = http("/status")
assert code == 200 and json.loads(body) == {}
srv.shutdown()

# Grafana annotations are sent with the API token when GRAFANA_TOKEN is set
got = []


class FakeGrafana(BaseHTTPRequestHandler):
    def do_POST(self):
        got.append((self.headers["Authorization"], json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


graf = ThreadingHTTPServer(("127.0.0.1", 0), FakeGrafana)
threading.Thread(target=graf.serve_forever, daemon=True).start()
engine.GRAFANA, engine.GRAFANA_TOKEN = f"http://127.0.0.1:{graf.server_address[1]}", "test-token"
new_minute()
alert("4")
for _ in range(50):
    if got:
        break
    time.sleep(0.05)
assert got and got[0][0] == "Bearer test-token" and "sentinel" in got[0][1]["tags"], got
engine.GRAFANA = ""
graf.shutdown()
release("4")

# Dry run: audit line written, nothing installed, so nothing to measure: released by hand only
engine.DRY_RUN = True
new_minute()
r = alert("9")
assert r["dry_run"] and r["rule_ids"] == [] and not LIVE
run(60)
assert (SW, "9") in engine.ACTIVE

# The engine also imports as a package: python -m sentinel.engine
subprocess.run([sys.executable, "-c", "import sentinel.engine"], cwd=os.path.dirname(HERE), check=True)

lines = audit_lines()
need = {"ts", "switch", "port", "type", "score", "confidence", "action", "onos_status", "rule_ids"}
assert all(need <= line.keys() for line in lines)
print(f"ok: {len(lines)} audit lines, all guardrails, playbooks, release checks and API behave")
