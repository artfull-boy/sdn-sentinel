#!/usr/bin/env bash
# Start the Sentinel mitigation engine in its own venv (mitvenv/), creating it on first run.
#
#   ./start-mitigation.sh               start the engine on :9202 (Ctrl-C releases every rule)
#   DRY_RUN=1 ./start-mitigation.sh     decide and log only, install nothing in the network
#   ./start-mitigation.sh test          offline self-check with a fake ONOS (~1 s)
#   ./start-mitigation.sh live-check    full live check; starts its own Mininet, so stop any
#                                       other Mininet first (needs sudo, ~2 min)
#
# Other settings (SENTINEL_TAU, ONOS_URL, GRAFANA_TOKEN, ...) are read from the environment and
# from the project's .env file if there is one; see docs/MITIGATION_README.md.
set -e
cd "$(dirname "$0")"
if [ -f .env ]; then set -a; . ./.env; set +a; fi  # e.g. GRAFANA_TOKEN for dashboard annotations
VENV=mitvenv
PY=$VENV/bin/python3
SYS_PY=/usr/bin/python3   # the system Python, where Mininet is installed

# (Re)install when the venv is missing or requirements-mitigation.txt changed.
if [ ! -x "$PY" ] || ! cmp -s requirements-mitigation.txt "$VENV/.installed-requirements"; then
  echo "Setting up $VENV ..."
  [ -x "$PY" ] || "$SYS_PY" -m venv "$VENV"
  "$PY" -m pip install -q -r requirements-mitigation.txt
  # Let the venv import the system Mininet library (needed by live_check.py only).
  MN_DIR=$("$SYS_PY" -c "import mininet, os; print(os.path.dirname(os.path.dirname(mininet.__file__)))" 2>/dev/null || true)
  if [ -n "$MN_DIR" ]; then
    echo "$MN_DIR" > "$("$PY" -c 'import site; print(site.getsitepackages()[0])')/system-mininet.pth"
  else
    echo "Note: Mininet not found in $SYS_PY; 'live-check' will not work, the engine will." >&2
  fi
  cp requirements-mitigation.txt "$VENV/.installed-requirements"
fi

case "${1:-start}" in
  start)      exec "$PY" sentinel/engine.py ;;
  test)       exec "$PY" sentinel/test_engine.py ;;
  live-check) exec sudo "$PY" sentinel/live_check.py ;;
  *)          echo "usage: $0 [start|test|live-check]" >&2; exit 2 ;;
esac
