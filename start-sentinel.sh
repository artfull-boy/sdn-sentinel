#!/usr/bin/env bash
# Start the whole Sentinel lab with one command.
#
#   ./start-sentinel.sh            start everything; ends at the mininet> prompt
#   ./start-sentinel.sh stop       stop detector, engine (releases its rules) and bridge exporter
#   ./start-sentinel.sh down       stop + stop the containers + clean Mininet
#   ./start-sentinel.sh status     what is running, Prometheus targets, ONOS hosts, active mitigations
#   ./start-sentinel.sh clean      remove phantom hosts from ONOS (run between attacks)
#   ./start-sentinel.sh logs       follow the service logs
#
# What "start" does, in order:
#   1. checks .env, the model and the Python env (.venv, scikit-learn 1.6.1)
#   2. docker compose up -d  (ONOS, Prometheus, Grafana) and waits for ONOS
#   3. stops any Sentinel services from an earlier run
#   4. removes phantom hosts left in ONOS by earlier floods (docker restart does NOT clear them)
#   5. starts the bridge exporter (:9200) and the mitigation engine (:9202) in the background
#   6. starts the detector (:9201) as soon as ONOS knows all real hosts, i.e. right after
#      you type `pingall`, so it learns every host at its real home port
#   7. starts the Mininet topology in this terminal (if it is not already running elsewhere)
#
# Options (environment variables):
#   DRY_RUN=1        engine decides and logs, installs nothing
#   NO_MININET=1     do not start Mininet (start it yourself)
#   SENTINEL_TAU=x   engine threshold; default: read from models/sentinel_model.joblib
#   REAL_HOSTS=6     how many real hosts must be known before the detector starts
#
# Services keep running after you leave Mininet; stop them with ./start-sentinel.sh stop.
# Logs: logs/{detector,engine,bridge_exporter}.out   PIDs: logs/run/*.pid
set -euo pipefail
cd "$(dirname "$0")"

ONOS_API=http://127.0.0.1:8181/onos/v1
ONOS_CRED=onos:rocks
MODEL=models/sentinel_model.joblib
VENV_PY=.venv/bin/python
RUN=logs/run
REAL_HOSTS=${REAL_HOSTS:-6}
mkdir -p "$RUN"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

onos() { curl -sf -m 5 -u "$ONOS_CRED" "$ONOS_API$1"; }
port_up() { curl -sf -m 2 -o /dev/null "http://127.0.0.1:$1/${2:-metrics}"; }

running() {  # running NAME -> true if its pid file points at a live process
  local f="$RUN/$1.pid"
  [ -f "$f" ] && kill -0 "$(cat "$f")" 2>/dev/null
}

start_bg() {  # start_bg NAME COMMAND... : detached, output in logs/NAME.out, pid in logs/run/NAME.pid
  local name=$1; shift
  setsid nohup "$@" >"logs/$name.out" 2>&1 </dev/null &
  echo $! >"$RUN/$name.pid"
}

stop_one() {  # stop_one NAME : SIGTERM, wait up to 15 s (the engine removes its rules on exit)
  local name=$1 f="$RUN/$1.pid" pid
  [ -f "$f" ] || return 0
  pid=$(cat "$f")
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -0 "$pid" 2>/dev/null && { warn "$name did not stop, killing it"; kill -KILL "$pid" 2>/dev/null || true; }
    echo "  stopped $name"
  fi
  rm -f "$f"
}

stop_services() {
  stop_one detector   # first, so it sends no more alerts while the engine shuts down
  stop_one engine
  stop_one bridge_exporter
  for p in 9200 9201 9202; do
    port_up $p && warn "port $p is still in use by a process this script did not start; stop it by hand"
  done
  return 0
}

clean_hosts() {  # delete hosts that have no IP and a locally administered (02:...) MAC
  onos /hosts | python3 -c '
import sys, json, base64, urllib.request
api, cred = sys.argv[1], sys.argv[2]
auth = "Basic " + base64.b64encode(cred.encode()).decode()
hosts = json.load(sys.stdin)["hosts"]
fake = [h for h in hosts if h["mac"].upper().startswith("02:") and not h["ipAddresses"]]
for h in fake:
    req = urllib.request.Request("%s/hosts/%s/%s" % (api, h["mac"], h["vlan"]),
                                 method="DELETE", headers={"Authorization": auth})
    urllib.request.urlopen(req, timeout=5)
print("  ONOS hosts: %d, removed %d phantom, %d left" % (len(hosts), len(fake), len(hosts) - len(fake)))
' "$ONOS_API" "$ONOS_CRED"
}

real_host_count() {
  onos /hosts 2>/dev/null | python3 -c 'import sys, json
print(sum(1 for h in json.load(sys.stdin)["hosts"] if h["ipAddresses"]))' 2>/dev/null || echo 0
}

mininet_running() { pgrep -f "topo/lab_topo.py" >/dev/null; }

status() {
  for s in bridge_exporter:9200 detector:9201 engine:9202; do
    n=${s%%:*}; p=${s##*:}
    if port_up "$p"; then st="up"; elif running "$n"; then st="starting / waiting"; else st="down"; fi
    printf '  %-16s :%s  %s\n' "$n" "$p" "$st"
  done
  if mininet_running; then echo "  mininet          running"; else echo "  mininet          not running"; fi
  docker ps --format '  {{.Names}}  {{.Status}}' --filter name=onos --filter name=prometheus --filter name=grafana
  echo "  ONOS real hosts: $(real_host_count)"
  curl -sf -m 3 http://127.0.0.1:9090/api/v1/targets | python3 -c 'import sys, json
print("  Prometheus targets: " + ", ".join("%s=%s" % (t["labels"]["job"], t["health"]) for t in json.load(sys.stdin)["data"]["activeTargets"]))' 2>/dev/null || echo "  Prometheus: not reachable"
  echo "  active mitigations: $(curl -sf -m 2 http://127.0.0.1:9202/status || echo 'engine down')"
}

preflight() {
  [ -f .env ] || die ".env missing: cp .env.example .env and set GF_SECURITY_ADMIN_PASSWORD"
  [ -f "$MODEL" ] || die "$MODEL missing: download it (docs/ML_DETECTOR_README.md section 1)"
  [ -x "$VENV_PY" ] || die ".venv missing. Python 3.14 cannot install scikit-learn 1.6.1; create it with Python 3.12:
     uv venv -p 3.12 .venv && uv pip install -p .venv/bin/python -r requirements.txt"
  "$VENV_PY" -c "import sklearn, joblib, prometheus_client; assert sklearn.__version__ == '1.6.1', sklearn.__version__" 2>/dev/null \
    || die ".venv does not have scikit-learn 1.6.1: uv pip install -p .venv/bin/python -r requirements.txt"
  command -v docker >/dev/null || die "docker not installed (run ./setup.sh)"
}

up() {
  preflight
  if [ "${NO_MININET:-}" != 1 ] && ! mininet_running; then
    sudo -v || die "sudo is needed for Mininet"   # ask for the password once, up front
  fi

  say "Starting ONOS, Prometheus and Grafana"
  docker compose up -d
  say "Waiting for ONOS (can take 1-2 minutes after a fresh start)"
  for i in $(seq 180); do
    apps=$(onos /applications 2>/dev/null | python3 -c 'import sys, json
print(" ".join(a["name"] for a in json.load(sys.stdin)["applications"] if a["state"] == "ACTIVE"))' 2>/dev/null || true)
    if [[ $apps == *org.onosproject.openflow* && $apps == *org.onosproject.fwd* ]]; then break; fi
    [ "$i" = 180 ] && die "ONOS not ready after 3 minutes: docker logs onos"
    sleep 1
  done
  echo "  ONOS is up (openflow + fwd active)"

  say "Stopping Sentinel services from an earlier run"
  stop_services

  say "Removing phantom hosts from ONOS"
  clean_hosts

  say "Starting the bridge exporter (:9200)"
  start_bg bridge_exporter python3 -u monitoring/bridge_exporter.py

  say "Starting the mitigation engine (:9202)${DRY_RUN:+  [DRY_RUN]}"
  if [ -z "${SENTINEL_TAU:-}" ]; then
    SENTINEL_TAU=$("$VENV_PY" -c "import joblib; print(round(float(joblib.load('$MODEL')['tau']), 4))")
  fi
  export SENTINEL_TAU
  echo "  tau = $SENTINEL_TAU"
  ./start-mitigation.sh test >/dev/null || die "engine self-test failed: ./start-mitigation.sh test"
  start_bg engine ./start-mitigation.sh

  for _ in $(seq 30); do port_up 9200 && port_up 9202 && break; sleep 1; done
  port_up 9200 || die "bridge exporter did not start: logs/bridge_exporter.out"
  port_up 9202 || die "engine did not start: logs/engine.out"
  echo "  $(head -1 logs/engine.out)"

  say "Detector (:9201) will start once ONOS knows all $REAL_HOSTS real hosts (after pingall)"
  start_bg detector "$0" _detector

  cat <<EOF

  Grafana     http://localhost:3000   (dashboard "Sentinel")
  Prometheus  http://localhost:9090/targets
  ONOS GUI    http://localhost:8181/onos/ui
  Release     http://localhost:9202/release
  Status      ./start-sentinel.sh status      Stop  ./start-sentinel.sh stop

EOF

  if [ "${NO_MININET:-}" = 1 ]; then
    say "NO_MININET=1: start the topology yourself, then type pingall"
  elif mininet_running; then
    say "Mininet is already running in another terminal: type 'pingall' there"
    if [ "$(real_host_count)" -ge "$REAL_HOSTS" ]; then echo "  (all hosts already known, the detector is starting now)"; fi
  else
    say "Starting Mininet. At the mininet> prompt type:  pingall"
    sudo mn -c >/dev/null 2>&1 || true
    sudo python3 topo/lab_topo.py --link-s3
    say "Mininet exited. Sentinel services are still running: ./start-sentinel.sh stop"
  fi
}

case "${1:-start}" in
  start|up) up ;;
  stop)     say "Stopping Sentinel services"; stop_services ;;
  down)     say "Stopping Sentinel services"; stop_services
            say "Stopping containers"; docker compose stop
            say "Cleaning Mininet"; sudo mn -c >/dev/null 2>&1 || true ;;
  status)   status ;;
  clean)    say "Removing phantom hosts from ONOS"; clean_hosts
            warn "restart the detector and engine so they relearn home ports: ./start-sentinel.sh" ;;
  logs)     tail -n 20 -F logs/bridge_exporter.out logs/engine.out logs/detector.out ;;
  _detector)  # internal: wait for pingall, then become the detector (same PID)
            until [ "$(real_host_count)" -ge "$REAL_HOSTS" ]; do sleep 2; done
            echo "all $REAL_HOSTS real hosts known in ONOS, starting the detector"
            exec "$VENV_PY" -u -m sentinel.detector --log logs/alerts.jsonl ;;
  *)        echo "usage: $0 [start|stop|down|status|clean|logs]" >&2; exit 2 ;;
esac
