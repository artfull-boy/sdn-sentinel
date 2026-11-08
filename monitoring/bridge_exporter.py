#!/usr/bin/env python3
"""Interim exporter on :9200. Publishes per-second rates and its own timing."""
import base64, json, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

ONOS = "http://localhost:8181/onos/v1/flows"
AUTH = "Basic " + base64.b64encode(b"onos:rocks").decode()
state = {"table": {}, "new": {}, "poll_s": 0.0, "last": time.time()}
lock = threading.Lock()

def poll():
    prev, t_prev = None, None
    while True:
        t0 = time.time()
        try:
            req = urllib.request.Request(ONOS, headers={"Authorization": AUTH})
            flows = json.load(urllib.request.urlopen(req, timeout=5))["flows"]
            ids = {}
            for f in flows:
                ids.setdefault(f["deviceId"], set()).add(f["id"])
            t1 = time.time()
            dt = (t1 - t_prev) if t_prev else None
            with lock:
                state["table"] = {d: len(s) for d, s in ids.items()}
                state["new"] = {d: (len(s - prev.get(d, set())) / dt if prev and dt else 0.0)
                                for d, s in ids.items()}
                state["poll_s"] = t1 - t0
                state["last"] = t1
            prev, t_prev = ids, t1
        except Exception as e:
            print("poll error:", e)
        time.sleep(max(0, 1 - (time.time() - t0)))

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404); self.end_headers(); return
        out = ["# TYPE sentinel_new_flows gauge", "# TYPE sentinel_table_size gauge",
               "# TYPE sentinel_poll_seconds gauge", "# TYPE sentinel_poll_age_seconds gauge"]
        with lock:
            for d, n in state["new"].items():
                out.append(f'sentinel_new_flows{{switch="{d}",port="all"}} {n:.2f}')
            for d, n in state["table"].items():
                out.append(f'sentinel_table_size{{switch="{d}"}} {n}')
            out.append(f'sentinel_poll_seconds {state["poll_s"]:.3f}')
            out.append(f'sentinel_poll_age_seconds {time.time() - state["last"]:.3f}')
        body = ("\n".join(out) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

threading.Thread(target=poll, daemon=True).start()
HTTPServer(("127.0.0.1", 9200), H).serve_forever()
