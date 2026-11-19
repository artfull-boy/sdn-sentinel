#!/usr/bin/env python3

# Sentinel detector

import argparse
import base64
import json
import os
import sys
import time
import urllib.request

import joblib
import numpy as np

from sentinel.features import FeatureWindow

ONOS = os.environ.get("ONOS_URL", "http://localhost:8181/onos/v1")
ONOS_USER = os.environ.get("ONOS_USER", "onos")
ONOS_PASS = os.environ.get("ONOS_PASS", "rocks")
RESEND_S = 10.0
TYPE_CODE = {"none": 0, "flood": 1, "slow_exhaustion": 2, "spoofing": 3, "unknown": 4}


# --------------------------------------------------------------------------
# ONOS snapshot: MUST stay identical to scenarios/raw_recorder.py, so live
# features are computed from exactly the same fields as the training data.
# --------------------------------------------------------------------------

def _get(path):
    req = urllib.request.Request(ONOS + path)
    token = base64.b64encode(("%s:%s" % (ONOS_USER, ONOS_PASS)).encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)


def _crit(criteria, kind, field):
    for c in criteria:
        if c.get("type") == kind:
            return c.get(field)
    return None


def onos_links():
    out = []
    for l in _get("/links").get("links", []):
        s, d = l.get("src", {}), l.get("dst", {})
        out.append({"src": "%s/%s" % (s.get("device"), s.get("port")),
                    "dst": "%s/%s" % (d.get("device"), d.get("port"))})
    return out


def onos_snapshot():
    flows = []
    for f in _get("/flows").get("flows", []):
        criteria = f.get("selector", {}).get("criteria", [])
        flows.append({"id": f.get("id"), "dev": f.get("deviceId"),
                      "inport": _crit(criteria, "IN_PORT", "port"),
                      "ethsrc": _crit(criteria, "ETH_SRC", "mac"),
                      "ethdst": _crit(criteria, "ETH_DST", "mac"),
                      "pkts": f.get("packets", 0)})
    ports = []
    for dev in _get("/statistics/ports").get("statistics", []):
        for p in dev.get("ports", []):
            ports.append({"dev": dev.get("device"), "port": p.get("port"),
                          "rx": p.get("packetsReceived", 0), "tx": p.get("packetsSent", 0)})
    hosts = []
    for h in _get("/hosts").get("hosts", []):
        loc = (h.get("locations") or [{}])[0]
        hosts.append({"mac": h.get("mac"), "dev": loc.get("elementId"), "port": loc.get("port")})
    return {"type": "sample", "ts": round(time.time(), 3),
            "flows": flows, "ports": ports, "hosts": hosts}


# --------------------------------------------------------------------------
# Model and per-port decision state
# --------------------------------------------------------------------------

def load_model(path, force=False):
    import sklearn
    m = joblib.load(path)
    missing = [k for k in ("iforest", "tau", "k", "rf", "min_conf", "features", "sklearn") if k not in m]
    if missing:
        sys.exit("model file is missing keys: %s" % missing)
    if m["sklearn"] != sklearn.__version__ and not force:
        sys.exit("model was saved with scikit-learn %s but %s is installed. Install "
                 "scikit-learn==%s (or pass --force)." % (m["sklearn"], sklearn.__version__, m["sklearn"]))
    m.setdefault("spoof_min_moves", 1)
    m.setdefault("spoof_hold", 5)
    m.setdefault("volume_hold", 0)       # models saved before the hold existed: no hold
    return m


class Detector:
    def __init__(self, model):
        self.m = model
        self.state = {}       # (switch, port) -> dict

    def score_rows(self, rows):
        """Return one decision dict per feature row (one per edge port)."""
        if not rows:
            return []
        m = self.m
        X = np.array([[r[f] for f in m["features"]] for r in rows], dtype=float)
        scores = -m["iforest"].score_samples(X)
        proba = m["rf"].predict_proba(X)
        out = []
        for r, s, p in zip(rows, scores, proba):
            key = (r["switch"], str(r["port"]))
            st = self.state.setdefault(key, {"consec": 0, "hold": 0, "vhold": 0, "alerting": False,
                                             "type": None, "last_sent": 0.0})
            st["consec"] = st["consec"] + 1 if s > m["tau"] else 0
            if st["consec"] >= m["k"]:
                st["vhold"] = m["volume_hold"] + 1
            volume = st["vhold"] > 0
            st["vhold"] = max(0, st["vhold"] - 1)
            if r.get("host_moves_in", 0) >= m["spoof_min_moves"]:
                st["hold"] = m["spoof_hold"] + 1
            identity = st["hold"] > 0
            st["hold"] = max(0, st["hold"] - 1)

            flagged = volume or identity
            best = int(p.argmax())
            conf = float(p[best])
            atype = str(m["rf"].classes_[best]) if conf >= m["min_conf"] else "unknown"
            out.append({"ts": r["ts"], "switch": key[0], "port": key[1], "score": float(s),
                        "flagged": flagged, "volume": volume, "identity": identity,
                        "type": atype if flagged else "none", "confidence": conf,
                        "new_flows": r["new_flows"]})
        return out

    def alerts(self, decisions):
        """Apply the send rule: first flag, type change, or every RESEND_S."""
        to_send = []
        for d in decisions:
            st = self.state[(d["switch"], d["port"])]
            if d["flagged"]:
                if (not st["alerting"] or d["type"] != st["type"]
                        or d["ts"] - st["last_sent"] >= RESEND_S):
                    reason = ("new" if not st["alerting"] else
                              "type change" if d["type"] != st["type"] else "still active")
                    to_send.append((reason, d))
                    st["last_sent"] = d["ts"]
                st["alerting"], st["type"] = True, d["type"]
            elif st["alerting"]:
                to_send.append(("cleared", d))
                st["alerting"], st["type"] = False, None
        return to_send


# --------------------------------------------------------------------------
# Output: engine, metrics, log
# --------------------------------------------------------------------------

def post_engine(url, d):
    body = json.dumps({"switch": d["switch"], "port": d["port"], "type": d["type"],
                       "score": round(d["score"], 4), "confidence": round(d["confidence"], 3),
                       "ts": d["ts"]}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/mitigate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.read().decode()[:200]
    except Exception as e:
        return "engine not reached (%s)" % e


class Metrics:
    def __init__(self, port):
        self.on = port > 0
        if not self.on:
            return
        from prometheus_client import Gauge, start_http_server
        lab = ["switch", "port"]
        # Not "sentinel_new_flows": that name belongs to monitoring/bridge_exporter.py
        # (per-second rate per switch), and monitoring/rules.yml sums every series of it.
        self.new_flows = Gauge("sentinel_window_new_flows", "New flows on the port in the 10 s window", lab)
        self.score = Gauge("sentinel_anomaly_score", "Isolation Forest anomaly score", lab)
        self.atype = Gauge("sentinel_attack_type",
                           "0 none, 1 flood, 2 slow_exhaustion, 3 spoofing, 4 unknown", lab)
        self.tau = Gauge("sentinel_tau", "Alert threshold on the anomaly score")
        start_http_server(port, addr="127.0.0.1")

    def update(self, decisions, tau):
        if not self.on:
            return
        self.tau.set(tau)
        for d in decisions:
            lab = (d["switch"], d["port"])
            self.new_flows.labels(*lab).set(d["new_flows"])
            self.score.labels(*lab).set(d["score"])
            self.atype.labels(*lab).set(TYPE_CODE.get(d["type"], 4))


def short(dev, port):
    return "s%d:%s" % (int(dev.split(":")[-1], 16), port) if dev.startswith("of:") else "%s:%s" % (dev, port)


# --------------------------------------------------------------------------
# Main loops
# --------------------------------------------------------------------------

def handle(det, metrics, rows, args, logf, summary):
    decisions = det.score_rows(rows)
    metrics.update(decisions, det.m["tau"])
    for reason, d in det.alerts(decisions):
        name = short(d["switch"], d["port"])
        if reason == "cleared":
            line = "%.1f  %-6s cleared" % (d["ts"], name)
            result = ""
        else:
            path = "+".join(p for p in ("volume", "identity") if d[p])
            result = "" if args.no_engine else post_engine(args.engine, d)
            line = "%.1f  %-6s ALERT %-12s %-15s score=%.3f conf=%.2f via %s %s" % (
                d["ts"], name, reason, d["type"], d["score"], d["confidence"], path,
                ("-> " + result) if result else "")
            summary.setdefault(name, []).append((d["ts"], d["type"]))
        print(line, flush=True)
        if logf:
            logf.write(json.dumps({"reason": reason, **d, "engine": result}) + "\n")
            logf.flush()


def run_replay(det, metrics, args, logf):
    summary, fw, t_first, prev_ts = {}, None, None, None
    with open(args.replay) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("type") == "meta":
                fw = FeatureWindow(obj.get("links", []))
                print("replaying %s" % obj.get("run_id"), flush=True)
                continue
            if obj.get("type") != "sample":
                continue
            fw = fw or FeatureWindow([])
            t_first = t_first or obj["ts"]
            if args.speed > 0 and prev_ts is not None:
                time.sleep(max(0.0, (obj["ts"] - prev_ts) / args.speed))
            prev_ts = obj["ts"]
            handle(det, metrics, fw.push(obj), args, logf, summary)
    print("\nsummary (seconds from start of recording):")
    if not summary:
        print("  no alerts")
    for name, hits in sorted(summary.items()):
        types = sorted({t for _, t in hits})
        print("  %-6s %d alerts, first at %.0f s, types %s" % (name, len(hits), hits[0][0] - t_first, types))


def run_live(det, metrics, args, logf):
    try:
        fw = FeatureWindow(onos_links())
    except Exception as e:
        sys.exit("cannot reach ONOS at %s (%s). Is the container up?" % (ONOS, e))
    print("live: polling %s every %.1f s, engine %s" % (
        ONOS, args.interval, "off" if args.no_engine else args.engine), flush=True)
    summary = {}
    while True:
        t0 = time.time()
        try:
            sample = onos_snapshot()
        except Exception as e:
            print("poll failed: %s" % e, file=sys.stderr, flush=True)
            time.sleep(args.interval)
            continue
        handle(det, metrics, fw.push(sample), args, logf, summary)
        took = time.time() - t0
        if took > args.interval:
            print("warning: poll+score took %.2f s (> %.1f s)" % (took, args.interval),
                  file=sys.stderr, flush=True)
        else:
            time.sleep(args.interval - took)


def main():
    p = argparse.ArgumentParser(description="Sentinel detector")
    p.add_argument("--model", default="models/sentinel_model.joblib")
    p.add_argument("--engine", default="http://localhost:9202")
    p.add_argument("--no-engine", action="store_true", help="log alerts only, send nothing")
    p.add_argument("--replay", help="score a recorded .jsonl instead of polling ONOS")
    p.add_argument("--speed", type=float, default=0, help="replay speed, 1 = real time, 0 = fast")
    p.add_argument("--interval", type=float, default=2.0, help="live poll interval (match the recordings)")
    p.add_argument("--metrics-port", type=int, default=None, help="Prometheus port (default 9201 live, off in replay)")
    p.add_argument("--log", help="append every alert as JSON to this file")
    p.add_argument("--force", action="store_true", help="skip the scikit-learn version check")
    args = p.parse_args()

    model = load_model(args.model, args.force)
    det = Detector(model)
    mport = args.metrics_port if args.metrics_port is not None else (0 if args.replay else 9201)
    metrics = Metrics(mport)
    print("model: %d features, tau=%.4f, k=%d, volume_hold=%d, min_conf=%.2f, types %s" % (
        len(model["features"]), model["tau"], model["k"], model["volume_hold"], model["min_conf"],
        list(model["rf"].classes_)))
    logf = open(args.log, "a") if args.log else None
    try:
        if args.replay:
            run_replay(det, metrics, args, logf)
        else:
            run_live(det, metrics, args, logf)
    except KeyboardInterrupt:
        pass
    finally:
        if logf:
            logf.close()


if __name__ == "__main__":
    main()
