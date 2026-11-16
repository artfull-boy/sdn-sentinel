#!/usr/bin/env python3
"""Sentinel mitigation engine on :9202.

POST /mitigate {switch, port, type, score, confidence, ts, victim_mac?} -> {action, rule_ids, dry_run}
POST /release  {switch, port}     remove every rule Sentinel put on that port
POST /pin      {switch, port}     keep that port's mitigation (no auto rollback)
GET  /metrics  Prometheus text,   GET /status  active mitigations
DRY_RUN=1      decide and audit, install nothing.
"""
import base64
import json
import os
import re
import threading
import time
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

import onos_client as onos

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AUDIT = os.path.join(ROOT, "logs", "audit.jsonl")
PLAYBOOKS = yaml.safe_load(open(os.path.join(HERE, "playbooks.yaml")))
DRY_RUN = os.environ.get("DRY_RUN") == "1"
DETECTOR_METRICS = os.environ.get("DETECTOR_METRICS", "http://127.0.0.1:9201/metrics")
GRAFANA = os.environ.get("GRAFANA_URL", "http://127.0.0.1:3000")
GRAFANA_AUTH = "Basic " + base64.b64encode(os.environ.get("GRAFANA_AUTH", "admin:admin").encode()).decode()
MIN_CONF = 0.6
MAX_ACTIONS_PER_MIN = 5

LOCK = threading.RLock()  # ponytail: one global lock, plenty for a handful of ports
ACTIVE = {}               # (switch, port) -> state of the mitigation on that port
ACTIONS = deque()         # times of new mitigations, for the 5 per minute guardrail
TOTALS = {}               # (switch, port) -> number of actions, for /metrics
HOME = {}                 # mac -> (switch, port) where ONOS first saw it


def load_tau():
    if os.environ.get("SENTINEL_TAU"):
        return float(os.environ["SENTINEL_TAU"])
    try:
        import joblib
        return float(joblib.load(os.path.join(ROOT, "models", "sentinel_model.joblib"))["tau"])
    except Exception:
        return None  # then only repeated /mitigate calls keep a port "hot"


TAU = load_tau()


def hot_ports():
    """Ports whose anomaly score on the detector's /metrics is above tau right now."""
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


def learn_hosts():
    try:
        seen = onos.hosts()
    except Exception:
        return
    with LOCK:
        for mac, loc in seen:
            HOME.setdefault(mac, loc)


def annotate(line):
    if not GRAFANA:
        return
    body = json.dumps({"time": int(line["ts"] * 1000), "tags": ["sentinel", line["action"]],
                       "text": f'{line["action"]} ({line["type"]}) on {line["switch"]} port {line["port"]}'}).encode()
    req = urllib.request.Request(GRAFANA + "/api/annotations", body,
                                 {"Content-Type": "application/json", "Authorization": GRAFANA_AUTH})
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


def install(key, pb, rules, victim_mac=""):
    """Apply one playbook. Appends rule ids ('flow:N', 'meter:N') to rules as they are made.
    Returns the action name, or None when a spoofing alert has no victim to protect."""
    sw, port = key
    act = pb["action"]
    if act == "drop_victim_mac":
        here = [mac for mac, loc in onos.hosts() if loc == key]
        # The detector's victim_mac wins, but only if ONOS really shows that MAC on this port,
        # so a detector bug can't get a random host blocked. Otherwise use our own memory.
        named = [mac for mac in here if victim_mac and mac.lower() == victim_mac.lower()]
        victims = named or [mac for mac in here if HOME.get(mac, key) != key]
        if not victims:
            return None
        for mac in ([] if DRY_RUN else victims):
            rules.append("flow:" + onos.drop_mac(sw, port, mac))
            rules.append("mac:" + mac)  # on release, purge fwd flows still pointing at the impostor
        return "drop_mac"
    if act == "meter" and not DRY_RUN:
        meter_id = onos.add_meter(sw, pb["rate_pps"])
        rules.append("meter:" + meter_id)
        rules.append("flow:" + onos.meter_port(sw, port, meter_id))
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
        now = time.time()
        if key in ACTIVE:
            ACTIVE[key]["last_hot"] = now
            return reply(audit(key, typ, score, conf, "refused:duplicate", **extra))
        try:
            infra = onos.infra_ports()
        except Exception as e:  # fail closed: no link map, no action
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
        ACTIVE[key] = dict(type=typ, rules=rules, started=now, last_hot=now,
                           escalated=False, pinned=False, score=score, confidence=conf)
        return reply(audit(key, typ, score, conf, action, "dry_run" if DRY_RUN else "ok", rules,
                           installed_ts=time.time(), **extra))


def release(req, why="manual"):
    key = (req["switch"], str(req["port"]))
    with LOCK:
        m = ACTIVE.pop(key, None)
        if not m:
            return reply(audit(key, None, None, None, "refused:not_active"))
        status = "dry_run" if DRY_RUN else remove(key[0], m["rules"])
        return reply(audit(key, m["type"], m["score"], m["confidence"], f"release:{why}", status, m["rules"]))


def pin(req):
    key = (req["switch"], str(req["port"]))
    with LOCK:
        m = ACTIVE.get(key)
        if not m:
            return reply(audit(key, None, None, None, "refused:not_active"))
        m["pinned"] = True
        return reply(audit(key, m["type"], m["score"], m["confidence"], "pin", rules=m["rules"]))


def tick(now=None, hot=None):
    """Once a second: refresh hot ports, escalate floods, roll back quiet ports."""
    now = now or time.time()
    hot = hot_ports() if hot is None else hot
    learn_hosts()
    with LOCK:
        for key, m in list(ACTIVE.items()):
            if key in hot:
                m["last_hot"] = now
            pb = PLAYBOOKS[m["type"]]
            esc = pb.get("escalate_to_drop_after_s")
            # Escalation is step 2 of the same incident, so it is not rate limited.
            if esc and not m["escalated"] and now - m["started"] >= esc and now - m["last_hot"] < 5:
                m["escalated"] = True
                try:
                    if not DRY_RUN:
                        m["rules"].append("flow:" + onos.drop_port(*key))
                    status = "dry_run" if DRY_RUN else "ok"
                except Exception as e:
                    status = f"error: {e}"
                TOTALS[key] += 1
                audit(key, m["type"], m["score"], m["confidence"], "drop", status, m["rules"])
            quiet = pb.get("release_after_quiet_s")
            if quiet is not None and not m["pinned"] and now - m["last_hot"] >= quiet:
                release({"switch": key[0], "port": key[1]}, "auto")


def metrics():
    active, totals = ["# TYPE sentinel_mitigation_active gauge"], ["# TYPE sentinel_actions_total counter"]
    with LOCK:
        for sw, port in sorted(set(TOTALS) | set(ACTIVE)):
            lbl = f'{{switch="{sw}",port="{port}"}}'
            active.append(f"sentinel_mitigation_active{lbl} {int((sw, port) in ACTIVE)}")
            totals.append(f"sentinel_actions_total{lbl} {TOTALS.get((sw, port), 0)}")
    return "\n".join(active + totals) + "\n"


ROUTES = {"/mitigate": mitigate, "/release": release, "/pin": pin}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/metrics":
            return self._send(200, metrics(), "text/plain; version=0.0.4")
        if self.path == "/status":
            with LOCK:
                return self._send(200, {f"{sw} {port}": m for (sw, port), m in ACTIVE.items()})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        fn = ROUTES.get(self.path)
        if not fn:
            return self._send(404, {"error": "not found"})
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if not isinstance(req, dict) or not req.get("switch") or req.get("port") in (None, ""):
                raise ValueError("switch and port are required")
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        self._send(200, fn(req))

    def log_message(self, *args):
        pass


def loop():
    while True:
        try:
            tick()
        except Exception as e:
            print("tick error:", e, flush=True)
        time.sleep(1)


if __name__ == "__main__":
    learn_hosts()
    threading.Thread(target=loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", 9202), Handler)
    print(f"sentinel engine on :9202  dry_run={DRY_RUN}  tau={TAU}  hosts_known={len(HOME)}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        for sw, port in list(ACTIVE):
            release({"switch": sw, "port": port}, "shutdown")
        print("released everything, bye")
