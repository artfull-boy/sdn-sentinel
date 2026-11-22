#!/usr/bin/env python3
"""Sentinel mitigation engine, HTTP API on 127.0.0.1:9202.

POST /mitigate {switch, port, type, score, confidence, ts, victim_mac?} -> {action, rule_ids, dry_run}
POST /release  {switch, port}     remove every rule Sentinel put on that port
POST /pin      {switch, port}     keep that port's mitigation exactly as it is (no automatic change)
GET  /status   active mitigations (JSON)       GET /metrics   Prometheus text
GET  /release  operator page: active mitigations with a Release button (linked from Grafana)
DRY_RUN=1      decide and audit, install nothing.
No timer removes a rule: release is decided from what the switch measures (see check_*).
Full reference with examples: docs/MITIGATION_README.md
"""
import base64
import html
import json
import os
import re
import signal
import threading
import time
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import yaml

try:
    from sentinel import onos_client as onos  # python -m sentinel.engine
except ImportError:
    import onos_client as onos  # python sentinel/engine.py

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AUDIT = os.path.join(ROOT, "logs", "audit.jsonl")
PLAYBOOKS = yaml.safe_load(open(os.path.join(HERE, "playbooks.yaml")))
DRY_RUN = os.environ.get("DRY_RUN") == "1"
HOST = os.environ.get("ENGINE_HOST", "127.0.0.1")  # localhost only, like ONOS, Prometheus and Grafana
PORT = 9202
DETECTOR_METRICS = os.environ.get("DETECTOR_METRICS", "http://127.0.0.1:9201/metrics")
GRAFANA =os.environ.get("GRAFANA_URL", "http://127.0.0.1:3000")
GRAFANA_TOKEN = os.environ.get("GRAFANA_TOKEN", "")
GRAFANA_AUTH = os.environ.get("GRAFANA_AUTH", "admin:admin")
# Browser POSTs (the Release button) are only accepted from Grafana or from the engine's own page,
# so another web page can't switch the defence off through the operator's browser.
ALLOWED_ORIGINS = {f"http://{h}:{p}" for h in ("localhost", "127.0.0.1") for p in (3000, PORT)} | {
    o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()}
MIN_CONF = 0.6
MAX_ACTIONS_PER_MIN = 5


def setting(name, default):
    return float(os.environ.get(name, default))


# Flood and slow flood: BLOCK (drop rule) <-> SAMPLE (meter to the controller), see check_block/check_sample
FLOOD_BLOCK_CHECK_S = setting("FLOOD_BLOCK_CHECK_S", 6)    # read the drop rule's counter this often
FLOOD_BLOCK_PKTS = setting("FLOOD_BLOCK_PKTS", 200)        # more dropped packets per check = keep blocking
FLOOD_SAMPLE_PPS = int(setting("FLOOD_SAMPLE_PPS", 8))     # meter rate while sampling
FLOOD_SAMPLE_CHECK_S = setting("FLOOD_SAMPLE_CHECK_S", 3)  # count new hosts on the port this often
FLOOD_NEW_HOSTS = setting("FLOOD_NEW_HOSTS", 5)            # more new MACs per check = still attacking
FLOOD_CONFIRM_CHECKS = int(setting("FLOOD_CONFIRM_CHECKS", 2))  # many new hosts this many times in a row = reblock
FLOOD_RELEASE_CHECKS = int(setting("FLOOD_RELEASE_CHECKS", 3))  # few new hosts this many times in a row = release
# (3 checks = 9 s: longer than the 6 s pauses of a pulsed flood, so a pause is not taken for the end)
# Spoofing: the MAC-drop rule's counter, see check_spoof
SPOOF_CHECK_S = setting("SPOOF_CHECK_S", 6)
SPOOF_MAX_PKTS = setting("SPOOF_MAX_PKTS", 0)              # more spoofed frames per check = keep the block
SPOOF_CONFIRM_CHECKS = int(setting("SPOOF_CONFIRM_CHECKS", 2))

LOCK = threading.RLock()  # ponytail: one global lock, plenty for a handful of ports
ACTIVE = {}               # (switch, port) -> state of the mitigation on that port
ACTIONS = deque()         # times of new mitigations, for the 5 per minute guardrail
TOTALS = {}               # (switch, port) -> number of actions, for /metrics
HOME = {}                 # mac -> (switch, port) where ONOS first saw it
INTERNAL = ("last_count", "known_macs", "next_check")  # state not shown in /status
clock = time.time         # replaced by the tests to simulate time


def load_tau():
    if os.environ.get("SENTINEL_TAU"):
        return float(os.environ["SENTINEL_TAU"])
    try:
        import joblib
        return float(joblib.load(os.path.join(ROOT, "models", "sentinel_model.joblib"))["tau"])
    except Exception:
        return None  # then only repeated /mitigate calls tell that a port is still attacking


TAU = load_tau()


def hot_ports():
    """Ports whose anomaly score on the detector's /metrics is above tau right now
    (only used for the flood escalation: meter -> drop after 15 s)."""
    if TAU is None:
        return set()
    try:
        text = urllib.request.urlopen(DETECTOR_METRICS, timeout=0.5).read().decode()
    except Exception:
        return set()
    hot = set()
    for labels, value in re.findall(r'^sentinel_anomaly_score\{([^}]*)\}\s+(\S+)', text, re.M):
        lbl = dict(re.findall(r'(\w+)="([^"]*)"', labels))
        if float(value) > TAU:
            hot.add((lbl.get("switch"), lbl.get("port")))
    return hot


INFRA = {"ports": None, "at": 0.0}  # switch-to-switch ports, cached: refreshed every second by tick()
INFRA_MAX_AGE_S = 5


def refresh_infra():
    INFRA["ports"], INFRA["at"] = onos.infra_ports(), time.time()


def infra_ports():
    """Switch-to-switch ports without a call to ONOS on the alert path: during a flood each ONOS
    call can take 1-2.5 s. Raises if the cache is too old and ONOS can't be reached (fail closed)."""
    if INFRA["ports"] is None or time.time() - INFRA["at"] > INFRA_MAX_AGE_S:
        refresh_infra()
    return INFRA["ports"]


def learn_hosts(seen=None):
    try:
        seen = onos.hosts() if seen is None else seen
    except Exception:
        return
    with LOCK:
        for mac, loc in seen:
            HOME.setdefault(mac, loc)


def grafana_auth():
    if GRAFANA_TOKEN:
        return "Bearer " + GRAFANA_TOKEN
    return "Basic " + base64.b64encode(GRAFANA_AUTH.encode()).decode()


def annotate(line):
    if not GRAFANA:
        return
    body = json.dumps({"time": int(line["ts"] * 1000), "tags": ["sentinel", line["action"]],
                       "text": f'{line["action"]} ({line["type"]}) on {line["switch"]} port {line["port"]}'}).encode()
    req = urllib.request.Request(GRAFANA + "/api/annotations", body,
                                 {"Content-Type": "application/json", "Authorization": grafana_auth()})
    try:
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass  # the dashboard is nice to have, the mitigation is not optional


def audit(key, typ, score, conf, action, status="skipped", rules=(), **extra):
    line = dict(ts=time.time(), switch=key[0], port=key[1], type=typ, score=score, confidence=conf,
                action=action, onos_status=status, rule_ids=list(rules), dry_run=DRY_RUN, **extra)
    os.makedirs(os.path.dirname(AUDIT), exist_ok=True)
    with open(AUDIT, "a") as f:
        f.write(json.dumps(line) + "\n")
    if not action.startswith("refused"):
        threading.Thread(target=annotate, args=(line,), daemon=True).start()
    return line


def reply(line):
    return {"action": line["action"], "rule_ids": line["rule_ids"], "dry_run": DRY_RUN}


def find_victims(key, victim_mac=""):
    """MACs to block on this port for a spoofing alert (ONOS spelling), [] if none."""
    here = [mac for mac, loc in onos.hosts() if loc == key]
    if victim_mac:
        # The detector's MAC is accepted if ONOS shows it here right now, or if its home is another
        # port. ONOS flips a victim that keeps talking between both ports, so "here right now" alone
        # misses it. A MAC seen nowhere is refused. The rule only drops that one MAC on this port,
        # so even a wrong value does no more harm than a false alert on this port would.
        for mac in here + list(HOME):
            if mac.lower() == victim_mac.lower() and (mac in here or HOME[mac] != key):
                return [mac]
    return [mac for mac in here if HOME.get(mac, key) != key]


def install(key, pb, rules, victim_mac=""):
    """Apply one playbook. Appends rule ids ('flow:N', 'meter:N', 'mac:M') to rules as they are made.
    Returns the action name, or None when a spoofing alert has no victim to protect."""
    sw, port = key
    act = pb["action"]
    if act == "drop_victim_mac":
        victims = find_victims(key, victim_mac)
        if not victims:
            return None
        for mac in ([] if DRY_RUN else victims):
            rules.append("flow:" + onos.drop_mac(sw, port, mac))
            rules.append("mac:" + mac)  # on release, purge fwd flows still pointing at the impostor
        return "drop_mac"
    if DRY_RUN:
        return act
    if act == "meter":
        meter_id = onos.add_meter(sw, pb["rate_pps"])
        rules.append("meter:" + meter_id)
        rules.append("flow:" + onos.meter_port(sw, port, meter_id))
    elif act == "drop":
        rules.append("flow:" + onos.drop_port(sw, port))
    return act


def remove(sw, rules):
    errors = []
    order = {"flow": 0, "mac": 1, "meter": 2}  # flows first: a meter in use can't be deleted
    for rule in sorted(rules, key=lambda r: order[r.split(":", 1)[0]]):
        kind, rid = rule.split(":", 1)
        try:
            if kind == "mac":
                onos.purge_mac_flows(rid)
            else:
                (onos.delete_meter if kind == "meter" else onos.delete_flow)(sw, rid)
        except Exception as e:
            errors.append(f"{rule}: {e}")
    return "ok" if not errors else "error: " + "; ".join(errors)


def phase_of(typ):
    """How a mitigation of this type ends: 'block' (flood cycle), 'spoof' (MAC rule counter),
    None (manual release only)."""
    return {"flood_cycle": "block", "spoof_counter": "spoof"}.get(PLAYBOOKS[typ].get("release"))


def fresh_state(typ, action, now):
    return dict(phase=phase_of(typ), last_count=None, known_macs=None, next_check=now,
                pos=0, neg=0, measured=None, last_hot=now, escalated=action == "drop")


def upgrade(key, m, typ, score, conf, victim_mac, extra):
    """An 'unknown' mitigation gets a named type: swap its rules for the named playbook.
    The detector often says 'unknown' first, while its window is still mostly normal traffic."""
    pb = PLAYBOOKS[typ]
    if pb["action"] == "drop_victim_mac" and not find_victims(key, victim_mac):
        return audit(key, typ, score, conf, "refused:duplicate", **extra)  # nothing better: stay metered
    # Old rules go first: a new rule with the same match and priority as an old one would be
    # overwritten in the switch, and deleting the old one afterwards would remove the new one.
    status = "dry_run" if DRY_RUN else remove(key[0], m["rules"])
    rules = []
    try:
        action = install(key, pb, rules, victim_mac)
    except Exception as e:
        remove(key[0], rules)
        ACTIVE.pop(key)  # the port is no longer covered; the detector's next alert starts over
        return audit(key, typ, score, conf, "failed", f"error: {e}", **extra)
    now = clock()
    m.update(type=typ, action=action, rules=rules, started=now, score=score, confidence=conf,
             **fresh_state(typ, action, now))
    TOTALS[key] += 1
    return audit(key, typ, score, conf, action, status, rules, upgraded_from="unknown",
                 installed_ts=time.time(), **extra)


def mitigate(req):
    key = (req["switch"], str(req["port"]))
    score, conf = float(req.get("score", 0)), float(req.get("confidence", 0))
    typ = req.get("type")
    if typ not in PLAYBOOKS or conf < MIN_CONF:
        typ = "unknown"
    victim_mac = str(req.get("victim_mac") or "")
    extra = {"alert_ts": float(req.get("ts") or time.time())}
    if victim_mac:
        extra["victim_mac"] = victim_mac  # what the detector claimed, kept in the audit line
    with LOCK:
        now = clock()
        m = ACTIVE.get(key)
        if m:
            m["last_hot"] = now  # the detector still reports this port (used by the flood escalation)
            if m["type"] == "unknown" and typ != "unknown":  # same incident, so not rate limited
                return reply(upgrade(key, m, typ, score, conf, victim_mac, extra))
            return reply(audit(key, typ, score, conf, "refused:duplicate", **extra))
        try:
            infra = infra_ports()
        except Exception as e:  # fail closed: no recent link map, no action
            return reply(audit(key, typ, score, conf, "refused:onos_unreachable", f"error: {e}", **extra))
        if key in infra:
            return reply(audit(key, typ, score, conf, "refused:infra_port", **extra))
        while ACTIONS and now - ACTIONS[0] > 60:
            ACTIONS.popleft()
        if len(ACTIONS) >= MAX_ACTIONS_PER_MIN:
            return reply(audit(key, typ, score, conf, "refused:rate_limit", **extra))

        pb, rules = PLAYBOOKS[typ], []
        try:
            action = install(key, pb, rules, victim_mac)
            if action is None:  # spoofing alert but no victim found: meter and flag instead
                typ, pb = "unknown", PLAYBOOKS["unknown"]
                action = install(key, pb, rules)
        except Exception as e:
            remove(key[0], rules)  # never leave half a mitigation behind
            return reply(audit(key, typ, score, conf, "failed", f"error: {e}", **extra))
        if pb.get("flag_human"):
            action += "+flag_human"
        ACTIONS.append(now)
        TOTALS[key] = TOTALS.get(key, 0) + 1
        ACTIVE[key] = dict(type=typ, action=action, rules=rules, started=now, pinned=False,
                           score=score, confidence=conf, **fresh_state(typ, action, now))
        return reply(audit(key, typ, score, conf, action, "dry_run" if DRY_RUN else "ok", rules,
                           installed_ts=time.time(), **extra))


def release(req, why="manual", **extra):
    key = (req["switch"], str(req["port"]))
    with LOCK:
        m = ACTIVE.pop(key, None)
        if not m:
            return reply(audit(key, None, None, None, "refused:not_active"))
        status = "dry_run" if DRY_RUN else remove(key[0], m["rules"])
        return reply(audit(key, m["type"], m["score"], m["confidence"], f"release:{why}", status, m["rules"],
                           **extra))


def pin(req):
    key = (req["switch"], str(req["port"]))
    with LOCK:
        m = ACTIVE.get(key)
        if not m:
            return reply(audit(key, None, None, None, "refused:not_active"))
        m["pinned"] = True
        return reply(audit(key, m["type"], m["score"], m["confidence"], "pin", rules=m["rules"]))


# ---- Ending a mitigation from measurements, no timers ---------------------------------------------

def read_counter(sw, rules):
    """(packets, refreshed_at, rule ids) of this mitigation's flow rules, from ONOS. refreshed_at is
    the OLDEST refresh among them, so a reading only counts once ONOS has updated every rule.
    None if it has no rule (dry run: nothing installed, nothing to measure)."""
    flows = tuple(r.split(":", 1)[1] for r in rules if r.startswith("flow:"))
    if not flows:
        return None
    total, at = 0, None
    for flow_id in flows:
        packets, seen = onos.flow_packets(sw, flow_id)
        total, at = total + packets, seen if at is None else min(at, seen)
    return total, at, flows


def counted_per_check(m, reading, period, now):
    """Packets that hit the rules during one check period, or None when there is nothing to compare
    yet. ONOS refreshes the counters only every ~5 s: a reading it has not refreshed is not used."""
    packets, seen, flows = reading
    last = m["last_count"]
    # New baseline: first reading, a counter that went down (rule reinstalled, switch restarted), or
    # a different set of rules (escalation added the drop rule: the meter rule stops counting and
    # ONOS reports the new rule's counter only at its next poll, so the old total would look flat).
    # Also when the baseline is too old to compare with (e.g. a rule ONOS had never polled yet).
    if last is None or packets < last[0] or flows != last[2] or seen - last[1] > 3 * period:
        m["last_count"], m["next_check"] = (packets, seen, flows), now + period
        return None
    if seen <= last[1]:
        m["next_check"] = now + 1  # ONOS has not refreshed every counter yet: look again in 1 s
        return None
    per_check = (packets - last[0]) / (seen - last[1]) * period
    m["last_count"], m["next_check"] = (packets, seen, flows), now + period
    m["measured"] = round(per_check, 1)
    return per_check


def swap_rules(key, m, pb, action, now, **extra):
    """Replace the port's rules (old ones first: same match and priority). On failure, try to put
    the drop back, so the port is never left open in the middle of an attack."""
    status = remove(key[0], m["rules"])
    rules = []
    try:
        install(key, pb, rules)
    except Exception as e:
        remove(key[0], rules)
        rules, status = [], f"error: {e}"
        try:
            install(key, {"action": "drop"}, rules)
            pb, action = {"action": "drop"}, "block"
        except Exception:
            ACTIVE.pop(key, None)
            return audit(key, m["type"], m["score"], m["confidence"], "failed", status, **extra)
    m.update(rules=rules, action=action, last_count=None, known_macs=None, pos=0, neg=0, next_check=now,
             phase="sample" if pb["action"] == "meter" else "block", escalated=pb["action"] == "drop")
    TOTALS[key] += 1
    return audit(key, m["type"], m["score"], m["confidence"], action, status, rules, **extra)


def check_block(key, m, reading, now):
    """BLOCK (drop rule): still many packets hitting it -> keep blocking; otherwise -> SAMPLE."""
    per_check = counted_per_check(m, reading, FLOOD_BLOCK_CHECK_S, now)
    if per_check is not None and per_check <= FLOOD_BLOCK_PKTS:
        swap_rules(key, m, {"action": "meter", "rate_pps": FLOOD_SAMPLE_PPS}, "sample", now,
                   dropped_per_check=m["measured"])


def check_sample(key, m, macs, now):
    """SAMPLE (meter: a few packets/s reach ONOS): count the new hosts (MACs) on this port.
    Many new hosts FLOOD_CONFIRM_CHECKS times in a row -> back to BLOCK (drop rule);
    few new hosts FLOOD_RELEASE_CHECKS times in a row -> release (no rules)."""
    m["next_check"] = now + FLOOD_SAMPLE_CHECK_S
    if m["known_macs"] is None:  # first check: just note who is on the port
        m["known_macs"] = sorted(macs)
        return
    new = set(macs) - set(m["known_macs"])
    m["known_macs"] = sorted(set(m["known_macs"]) | set(macs))
    m["measured"] = len(new)
    if len(new) > FLOOD_NEW_HOSTS:
        m["pos"], m["neg"] = m["pos"] + 1, 0
    else:
        m["pos"], m["neg"] = 0, m["neg"] + 1
    if m["pos"] >= FLOOD_CONFIRM_CHECKS:
        swap_rules(key, m, {"action": "drop"}, "reblock", now, new_hosts_per_check=len(new))
    elif m["neg"] >= FLOOD_RELEASE_CHECKS:
        release({"switch": key[0], "port": key[1]}, "auto", new_hosts_per_check=len(new))


def check_spoof(key, m, reading, now):
    """MAC-drop rule: every packet counted is a spoofed frame. More than SPOOF_MAX_PKTS per check
    keeps the block; at most that SPOOF_CONFIRM_CHECKS times in a row -> release."""
    per_check = counted_per_check(m, reading, SPOOF_CHECK_S, now)
    if per_check is None:
        return
    m["pos"], m["neg"] = (m["pos"] + 1, 0) if per_check > SPOOF_MAX_PKTS else (0, m["neg"] + 1)
    if m["neg"] >= SPOOF_CONFIRM_CHECKS:
        release({"switch": key[0], "port": key[1]}, "auto", spoofed_per_check=m["measured"])


def escalate(key, m, now):
    """Flood playbook step 2 (project plan): meter at the alert, then a drop rule if the detector
    still reports the port after escalate_to_drop_after_s. Not rate limited: same incident."""
    m["escalated"], m["action"] = True, "drop"
    try:
        if not DRY_RUN:
            m["rules"].append("flow:" + onos.drop_port(*key))
        status = "dry_run" if DRY_RUN else "ok"
    except Exception as e:
        status = f"error: {e}"
    TOTALS[key] += 1
    audit(key, m["type"], m["score"], m["confidence"], "drop", status, m["rules"])


def tick(now=None, hot=None):
    """Once a second: refresh what the engine knows, escalate floods, run the checks that are due."""
    now = now or clock()
    hot = hot_ports() if hot is None else hot
    try:
        seen = onos.hosts()
    except Exception:
        seen = None
    learn_hosts(seen)
    try:
        refresh_infra()
    except Exception:
        pass  # the cache ages out after INFRA_MAX_AGE_S and new mitigations are then refused
    with LOCK:
        for key, m in ACTIVE.items():
            if key in hot:
                m["last_hot"] = now
            esc = PLAYBOOKS[m["type"]].get("escalate_to_drop_after_s")
            if (esc and m["phase"] == "block" and not m["escalated"] and not m["pinned"]
                    and now - m["started"] >= esc and now - m["last_hot"] < 5):
                escalate(key, m, now)
        due ={k: (m["phase"], list(m["rules"])) for k, m in ACTIVE.items()
               if m["phase"] and not m["pinned"] and now >= m["next_check"]}
    readings = {}
    for key, (phase, rules) in due.items():  # outside the lock: ONOS can be slow during a flood
        try:
            if phase == "sample":
                if seen is not None:
                    readings[key] = [mac for mac, loc in seen if loc == key]
            else:
                readings[key] = read_counter(key[0], rules)
        except Exception:
            pass  # ONOS did not answer: no decision this time, the rules stay as they are
    with LOCK:
        for key, value in readings.items():
            m = ACTIVE.get(key)
            if not m or value is None or m["phase"] != due[key][0] or m["pinned"]:
                continue
            {"block": check_block, "sample": check_sample, "spoof": check_spoof}[m["phase"]](key, m, value, now)


def metrics():
    fams = {"sentinel_mitigation_active": "gauge", "sentinel_actions_total": "counter",
            "sentinel_flag_human": "gauge", "sentinel_mitigation_info": "gauge",
            "sentinel_mitigation_measured": "gauge"}
    out = {name: [f"# TYPE {name} {kind}"] for name, kind in fams.items()}
    with LOCK:
        for sw, port in sorted(set(TOTALS) | set(ACTIVE)):
            m = ACTIVE.get((sw, port))
            lbl = f'switch="{sw}",port="{port}"'
            out["sentinel_mitigation_active"].append(f"sentinel_mitigation_active{{{lbl}}} {int(bool(m))}")
            out["sentinel_actions_total"].append(f"sentinel_actions_total{{{lbl}}} {TOTALS.get((sw, port), 0)}")
            flag = int(bool(m and PLAYBOOKS[m["type"]].get("flag_human")))
            out["sentinel_flag_human"].append(f"sentinel_flag_human{{{lbl}}} {flag}")
            if m:  # one row per active mitigation, for a Grafana table
                out["sentinel_mitigation_info"].append(
                    f'sentinel_mitigation_info{{{lbl},type="{m["type"]}",action="{m["action"]}",'
                    f'phase="{m["phase"] or "manual"}",pinned="{int(m["pinned"])}",flag_human="{flag}"}} 1')
                if m["measured"] is not None:  # last measurement: dropped/spoofed packets or new hosts per check
                    out["sentinel_mitigation_measured"].append(
                        f'sentinel_mitigation_measured{{{lbl},phase="{m["phase"]}"}} {m["measured"]}')
    return "\n".join(line for lines in out.values() for line in lines) + "\n"


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Sentinel mitigations</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>
body{font:15px system-ui,sans-serif;margin:24px;color:#222}h1{font-size:20px}
table{border-collapse:collapse}td,th{border-bottom:1px solid #ddd;padding:6px 10px;text-align:left}
button{padding:4px 14px;cursor:pointer}.flag{color:#b00;font-weight:600}</style></head>
<body><h1>Sentinel mitigations</h1>{body}</body></html>"""

UNITS = {"block": "dropped packets per check", "sample": "new hosts per check", "spoof": "spoofed frames per check"}


def measured_cell(m):
    if not m["phase"]:
        return "manual release"
    if m["measured"] is None:
        return "measuring"
    return f"{m['measured']} {UNITS[m['phase']]}"


def release_page(sw=None, port=None):
    """Operator page: the active mitigations (or one port's), each with a Release button."""
    esc = html.escape
    with LOCK:
        items = [(k, dict(m)) for k, m in sorted(ACTIVE.items()) if not sw or k == (sw, str(port))]
    if not items:
        where = f" on {esc(sw)} port {esc(str(port))}" if sw else ""
        body = f"<p>No active mitigation{where}.</p>"
    else:
        rows = "".join(
            f"<tr><td>{esc(s)}</td><td>{esc(p)}</td><td>{esc(m['type'])}</td>"
            f"<td{' class=flag' if 'flag_human' in m['action'] else ''}>{esc(m['action'])}</td>"
            f"<td>{int(clock() - m['started'])} s</td><td>{esc(measured_cell(m))}</td>"
            f"<td>{'yes' if m['pinned'] else 'no'}</td>"
            f"<td><form method='post' action='/release'><input type='hidden' name='switch' value='{esc(s)}'>"
            f"<input type='hidden' name='port' value='{esc(p)}'><button>Release</button></form></td></tr>"
            for (s, p), m in items)
        body = ("<table><tr><th>Switch</th><th>Port</th><th>Type</th><th>Action</th><th>Active for</th>"
                f"<th>Last measurement</th><th>Pinned</th><th></th></tr>{rows}</table>")
    if sw:
        body += "<p><a href='/release'>All active mitigations</a></p>"
    return PAGE.replace("{body}", body)


def result_page(out, req):
    esc = html.escape
    return PAGE.replace("{body}", f"<p><b>{esc(out['action'])}</b> on {esc(req['switch'])} port "
                                  f"{esc(str(req['port']))}.</p><p><a href='/release'>Back to active mitigations</a></p>")


ROUTES = {"/mitigate": mitigate, "/release": release, "/pin": pin}
HTML = "text/html; charset=utf-8"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = (body if isinstance(body, str) else json.dumps(body)).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client stopped waiting; the action itself was already applied and audited

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/metrics":
            return self._send(200, metrics(), "text/plain; version=0.0.4")
        if url.path == "/status":
            with LOCK:
                return self._send(200, {f"{sw} {port}": {k: v for k, v in m.items() if k not in INTERNAL}
                                        for (sw, port), m in ACTIVE.items()})
        if url.path == "/release":
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            return self._send(200, release_page(q.get("switch"), q.get("port")), HTML)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        fn = ROUTES.get(urlsplit(self.path).path)
        if not fn:
            return self._send(404, {"error": "not found"})
        origin = self.headers.get("Origin")
        if origin and origin not in ALLOWED_ORIGINS:  # curl and the detector send no Origin
            return self._send(403, {"error": f"origin {origin} not allowed"})
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            # Decide by the body, not Content-Type: `curl -d '{...}'` labels JSON as a form.
            form = bool(raw.strip()) and not raw.lstrip().startswith(b"{")  # the Release button
            req = {k: v[0] for k, v in parse_qs(raw.decode()).items()} if form else json.loads(raw or b"{}")
            if not isinstance(req, dict) or not req.get("switch") or req.get("port") in (None, ""):
                raise ValueError("switch and port are required")
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        out = fn(req)
        if form:  # the Release button on the operator page
            return self._send(200, result_page(out, req), HTML)
        self._send(200, out)

    def log_message(self, *args):
        pass


def loop():
    while True:
        try:
            tick()
        except Exception as e:
            print("tick error:", e, flush=True)
        time.sleep(1)


def stop(*_):
    raise KeyboardInterrupt


if __name__ == "__main__":
    # Ctrl-C and `kill` both release every rule first, even when started in the background
    # (a background job starts with Ctrl-C ignored, so Python would not catch it by itself).
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    learn_hosts()
    threading.Thread(target=loop, daemon=True).start()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"sentinel engine on {HOST}:{PORT}  dry_run={DRY_RUN}  tau={TAU}  hosts_known={len(HOME)}  "
          f"flood: block>{FLOOD_BLOCK_PKTS:g} pkts/{FLOOD_BLOCK_CHECK_S:g}s, sample {FLOOD_SAMPLE_PPS} pkt/s, "
          f">{FLOOD_NEW_HOSTS:g} new hosts/{FLOOD_SAMPLE_CHECK_S:g}s x{FLOOD_CONFIRM_CHECKS}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        for sw, port in list(ACTIVE):
            release({"switch": sw, "port": port}, "shutdown")
        print("released everything, bye")
