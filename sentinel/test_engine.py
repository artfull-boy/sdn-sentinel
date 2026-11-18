"""Offline check of playbooks, guardrails, rollback and the HTTP API, with a fake ONOS.
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
H3, H6 = "00:00:00:00:00:03", "00:00:00:00:00:06"
LIVE, counter = set(), iter(range(100, 10**6))
HOSTS = [(H6, (SW, "6")), (H3, (SW, "2"))]  # h6 lives on port 6, h3 on port 2


def fake(kind):
    def make(*args):
        rid = str(next(counter))
        LIVE.add(f"{kind}:{rid}")
        return rid
    return make


onos.infra_ports = lambda: {(SW, "3")}  # s1 port 3 goes to another switch
onos.hosts = lambda: HOSTS
onos.add_meter = fake("meter")
onos.meter_port = onos.drop_port = onos.drop_mac = fake("flow")
onos.delete_flow = lambda sw, rid: LIVE.discard(f"flow:{rid}")
onos.delete_meter = lambda sw, rid: LIVE.discard(f"meter:{rid}")
PURGED = []
onos.purge_mac_flows = PURGED.append
engine.AUDIT = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
engine.GRAFANA = ""


def alert(port, typ="flood", conf=0.9, **more):
    return engine.mitigate({"switch": SW, "port": port, "type": typ, "score": 1.0, "confidence": conf,
                            "ts": time.time(), **more})


def release(port):
    return engine.release({"switch": SW, "port": port})


def last_audit():
    return json.loads(open(engine.AUDIT).read().splitlines()[-1])


def new_minute():  # forget earlier actions so the 5 per minute guardrail doesn't interfere
    engine.ACTIONS = engine.deque()


engine.learn_hosts()
t0 = time.time()

# Guardrail: switch-to-switch port is refused
assert alert("3")["action"] == "refused:infra_port"

# Flood: meter + metered flow, duplicate refused, drop after 15 s while hot, release after 30 s quiet
r = alert("1")
assert r["action"] == "meter" and len(r["rule_ids"]) == 2, r
assert alert("1")["action"] == "refused:duplicate"
engine.tick(now=t0 + 16, hot={(SW, "1")})
assert len(engine.ACTIVE[(SW, "1")]["rules"]) == 3 and engine.ACTIVE[(SW, "1")]["action"] == "drop"
engine.tick(now=t0 + 16 + 31, hot=set())
assert (SW, "1") not in engine.ACTIVE and not LIVE, LIVE

# Re-offender: the same port attacked again within 5 min of an automatic release goes straight to drop,
# is not escalated a second time, and waits 4 x 30 s before the next release
r = alert("1")
assert r["action"] == "drop" and len(r["rule_ids"]) == 1 and last_audit()["reoffend"] is True, r
now = time.time()
engine.tick(now=now + 16, hot={(SW, "1")})
assert len(engine.ACTIVE[(SW, "1")]["rules"]) == 1
engine.tick(now=now + 16 + 60, hot=set())
assert (SW, "1") in engine.ACTIVE
engine.tick(now=now + 16 + 121, hot=set())
assert (SW, "1") not in engine.ACTIVE and not LIVE

# Spoofing from memory: h6 now shows up on port 2, drop h6's MAC there only
HOSTS[:] = [(H6, (SW, "2")), (H3, (SW, "2"))]
new_minute()
r = alert("2", "spoofing")
assert r["action"] == "drop_mac" and r["rule_ids"][1] == "mac:" + H6, r

# Low confidence becomes unknown: meter + flag, never auto released; spoofing rolls back after 60 s
assert alert("4", conf=0.3)["action"] == "meter+flag_human"
engine.tick(now=t0 + 1000, hot=set())
assert (SW, "4") in engine.ACTIVE
assert (SW, "2") not in engine.ACTIVE and PURGED == [H6]  # and h6's stale fwd flows were purged

# Upgrade unknown -> flood: the unknown meter is replaced by the flood playbook (not a duplicate)
old = set(engine.ACTIVE[(SW, "4")]["rules"])
r = alert("4", "flood")
assert r["action"] == "meter" and last_audit()["upgraded_from"] == "unknown", r
assert engine.ACTIVE[(SW, "4")]["type"] == "flood" and not (old & LIVE) and LIVE == set(r["rule_ids"])
engine.tick(now=time.time() + 16, hot={(SW, "4")})  # and it escalates like any flood
assert engine.ACTIVE[(SW, "4")]["action"] == "drop"
release("4")

# Upgrade unknown -> spoofing: the meter goes, the MAC block comes (detector says unknown first)
new_minute()
assert alert("2", "unknown")["action"] == "meter+flag_human"
r = alert("2", "spoofing")
assert r["action"] == "drop_mac" and LIVE == {r["rule_ids"][0]}, (r, LIVE)
release("2")

# ONOS flipped h6 back home: no victim on port 2 right now, so the upgrade is refused (stays metered)...
HOSTS[:] = [(H6, (SW, "6")), (H3, (SW, "2"))]
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

# Pin keeps a flood mitigation past its rollback time
new_minute()
alert("5")
engine.pin({"switch": SW, "port": "5"})
engine.tick(now=t0 + 2000, hot=set())
assert (SW, "5") in engine.ACTIVE
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
        f'pinned="0",reoffend="0",flag_human="1"}} 1') in text
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
assert code == 200 and "Release</button>" in page and "meter+flag_human" in page
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
assert http("/release", json.dumps({"switch": SW, "port": "4"}).encode())[0] == 200
assert http("/mitigate", b"not json")[0] == 400
assert http("/mitigate", b'{"port": "4"}')[0] == 400
assert http("/nope")[0] == 404
code, text = http("/metrics")
assert code == 200 and "# TYPE sentinel_mitigation_info gauge" in text
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

# Dry run: audit line written, nothing installed
engine.DRY_RUN = True
new_minute()
r = alert("9")
assert r["dry_run"] and r["rule_ids"] == [] and not LIVE

# The engine also imports as a package: python -m sentinel.engine
subprocess.run([sys.executable, "-c", "import sentinel.engine"], cwd=os.path.dirname(HERE), check=True)

lines = [json.loads(line) for line in open(engine.AUDIT)]
need = {"ts", "switch", "port", "type", "score", "confidence", "action", "onos_status", "rule_ids"}
assert all(need <= line.keys() for line in lines)
print(f"ok: {len(lines)} audit lines, all guardrails, playbooks and API behave")
