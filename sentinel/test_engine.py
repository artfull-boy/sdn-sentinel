"""Offline check of playbooks, guardrails and rollback with a fake ONOS.
Run: python3 sentinel/test_engine.py"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine  # noqa: E402
import onos_client as onos  # noqa: E402

SW = "of:0000000000000001"
H6 = "00:00:00:00:00:06"
LIVE, counter = set(), iter(range(100, 10**6))
HOSTS = [(H6, (SW, "6"))]


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


def alert(port, typ="flood", conf=0.9):
    return engine.mitigate({"switch": SW, "port": port, "type": typ, "score": 1.0, "confidence": conf, "ts": time.time()})


engine.learn_hosts()  # h6 lives on port 6
t0 = time.time()

# Guardrail: switch-to-switch port is refused
assert alert("3")["action"] == "refused:infra_port"

# Flood: meter + metered flow, duplicate refused, drop after 15 s while hot, release after 30 s quiet
r = alert("1")
assert r["action"] == "meter" and len(r["rule_ids"]) == 2, r
assert alert("1")["action"] == "refused:duplicate"
engine.tick(now=t0 + 16, hot={(SW, "1")})
assert len(engine.ACTIVE[(SW, "1")]["rules"]) == 3
engine.tick(now=t0 + 16 + 31, hot=set())
assert (SW, "1") not in engine.ACTIVE and not LIVE, LIVE

# Spoofing: h6 now shows up on port 2, drop h6's MAC there only
HOSTS[:] = [(H6, (SW, "2")), ("00:00:00:00:00:02", (SW, "2"))]
engine.learn_hosts()
r = alert("2", "spoofing")
assert r["action"] == "drop_mac" and r["rule_ids"][1] == "mac:" + H6, r

# Low confidence becomes unknown: meter + flag, never auto released
assert alert("4", conf=0.3)["action"] == "meter+flag_human"
engine.tick(now=t0 + 1000, hot=set())
assert (SW, "4") in engine.ACTIVE
assert (SW, "2") not in engine.ACTIVE  # the spoofing block did roll back after 60 s quiet
assert PURGED == [H6]                   # and h6's stale fwd flows were purged

# Pin keeps a flood mitigation past its rollback time
alert("5")
engine.pin({"switch": SW, "port": "5"})
engine.tick(now=t0 + 2000, hot=set())
assert (SW, "5") in engine.ACTIVE

# Rate limit: actions so far this minute = 1, 2, 4, 5 -> one more is fine, the 6th is refused
assert alert("7")["action"] == "meter"
assert alert("8")["action"] == "refused:rate_limit"

# Manual release cleans up everything
for port in ("4", "5", "7"):
    assert engine.release({"switch": SW, "port": port})["action"] == "release:manual"
assert not engine.ACTIVE and not LIVE, LIVE

# Spoofing with no prior knowledge: the engine first sees h6 already on the impostor port
engine.HOME.clear()
engine.ACTIONS = engine.deque()
HOSTS[:] = [(H6, (SW, "2")), ("00:00:00:00:00:03", (SW, "2"))]
engine.learn_hosts()


def spoof(victim_mac=None):
    req = {"switch": SW, "port": "2", "type": "spoofing", "score": 1.0, "confidence": 0.9}
    if victim_mac:
        req["victim_mac"] = victim_mac
    return engine.mitigate(req)


assert spoof()["action"] == "meter+flag_human"                        # no history, no hint: fallback
engine.release({"switch": SW, "port": "2"})
assert spoof("00:00:00:00:00:01")["action"] == "meter+flag_human"     # h1 is not on that port: hint ignored
engine.release({"switch": SW, "port": "2"})
r = spoof(H6.lower())                                                # the detector names h6: precise block
assert r["action"] == "drop_mac" and r["rule_ids"][1] == "mac:" + H6, r
assert json.loads(open(engine.AUDIT).read().splitlines()[-1])["victim_mac"] == H6.lower()
del PURGED[:]
engine.release({"switch": SW, "port": "2"})
assert PURGED == [H6] and not engine.ACTIVE and not LIVE, (PURGED, LIVE)

# Dry run: audit line written, nothing installed
engine.DRY_RUN, engine.ACTIONS = True, engine.deque()
r = alert("9")
assert r["dry_run"] and r["rule_ids"] == [] and not LIVE

lines = [json.loads(line) for line in open(engine.AUDIT)]
need = {"ts", "switch", "port", "type", "score", "confidence", "action", "onos_status", "rule_ids"}
assert all(need <= line.keys() for line in lines)
print(f"ok: {len(lines)} audit lines, all guardrails and playbooks behave")
