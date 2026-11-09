#!/usr/bin/env bash
# End-to-end smoke test for the testbed and recorder.
# RUN THIS WHILE THE TOPOLOGY IS ALREADY RUNNING in another terminal:
#   sudo python3 topo/lab_topo.py --link-s3
# It does a short flood, records it, and validates the capture file.
#
# FLAGS: none. Writes a throwaway capture to data/raw/_smoke.jsonl.
set -u

CAP=data/raw/_smoke.jsonl
ONOS="http://localhost:8181/onos/v1"
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== 1. ONOS reachable =="
if curl -s -u onos:rocks "$ONOS/devices" | grep -q '"of:'; then
  ok "ONOS answering, switches present"
else
  no "ONOS not reachable or no switches (is docker compose up and topology running?)"; exit 1
fi

echo "== 2. h1 namespace present =="
H1=$(pgrep -f "mininet:h1$" | head -1)
if [ -n "$H1" ]; then ok "h1 pid $H1"; else no "h1 not found; is the topology running?"; exit 1; fi

echo "== 3. record 15s while flooding 10s =="
python3 scenarios/raw_recorder.py "$CAP" --duration 15 &
REC=$!
sleep 2
sudo mnexec -a "$H1" python3 scenarios/attacks/flood.py --rate 20 --duration 10
wait $REC
if [ -f "$CAP" ]; then ok "capture file written"; else no "no capture file"; exit 1; fi

echo "== 4. validate capture contents =="
python3 - "$CAP" << 'PY'
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
meta = lines[0]
samples = [l for l in lines if l.get("type") == "sample"]
checks = []
checks.append(("meta line first", meta.get("type") == "meta"))
checks.append(("meta has links", isinstance(meta.get("links"), list) and len(meta["links"]) > 0))
checks.append(("at least 8 samples", len(samples) >= 8))
checks.append(("samples have ts (epoch)", all(isinstance(s.get("ts"), (int,float)) and s["ts"] > 1e9 for s in samples)))
checks.append(("flows populated", any(len(s["flows"]) > 0 for s in samples)))
checks.append(("ports populated", any(len(s["ports"]) > 0 for s in samples)))
checks.append(("hosts populated", any(len(s["hosts"]) > 0 for s in samples)))
checks.append(("flood visible (>50 flows at peak)", max((len(s["flows"]) for s in samples), default=0) > 50))
f = next((s for s in samples if s["flows"]), None)
checks.append(("flow has id+dev+pkts fields", f is not None and all(k in f["flows"][0] for k in ("id","dev","pkts"))))
for name, good in checks:
    print(("  PASS: " if good else "  FAIL: ") + name)
sys.exit(0 if all(g for _,g in checks) else 1)
PY
VAL=$?
if [ $VAL -eq 0 ]; then ok "capture contents valid"; else no "capture contents invalid (see above)"; fi

echo
echo "== summary: $PASS passed, $FAIL failed =="
rm -f "$CAP"
[ $FAIL -eq 0 ] && echo "ALL GOOD, ready to record" || echo "FIX ISSUES before recording"
