# Sentinel mitigation engine

The mitigation engine is the part of Sentinel that **reacts** to an attack. The detector tells it
"switch X, port Y is under attack of type Z", and the engine puts a countermeasure on that one
switch port through ONOS. It logs every decision and removes the countermeasure once the attack is over.

It is a small HTTP API server (JSON) on **`127.0.0.1:9202`**, written with the Python standard library.
Owner: Abdo. Questions about the API: see section 6, every endpoint has a copy-paste example.

## 1. Quick start (in the VM, from the project folder)

```bash
docker compose up -d                                  # ONOS (+ Prometheus, Grafana)
```
```bash
sudo mn -c && sudo python3 topo/lab_topo.py --link-s3  # topology; then type: pingall
```
```bash
./start-mitigation.sh                                 # the engine, in another terminal
```
It prints `sentinel engine on 127.0.0.1:9202  dry_run=False  tau=...  hosts_known=...`.
Stop it with **Ctrl-C**: it removes every rule it installed before exiting.

Try it from a 4th terminal:
```bash
curl -s -XPOST localhost:9202/mitigate -d '{"switch":"of:0000000000000001","port":"1","type":"flood","score":0.9,"confidence":0.9}'
```
```bash
curl -s localhost:9202/status
```
```bash
curl -s -XPOST localhost:9202/release -d '{"switch":"of:0000000000000001","port":"1"}'
```
Or open **http://localhost:9202/release** in the VM's browser to see and release mitigations.

## 2. Files

| File | What it is |
|---|---|
| `sentinel/engine.py` | The API server: decisions, guardrails, rollback, metrics, audit log, release page |
| `sentinel/onos_client.py` | Talks to the ONOS REST API (meters, flow rules, links, hosts) |
| `sentinel/playbooks.yaml` | Which countermeasure to use for each attack type |
| `sentinel/test_engine.py` | Offline test with a fake ONOS (no network needed) |
| `sentinel/live_check.py` | Full test against the real ONOS and Mininet |
| `start-mitigation.sh` | Starts the engine (or its tests) in its own venv, `mitvenv/` |
| `requirements-mitigation.txt` | What `mitvenv/` contains: only PyYAML; the rest is the standard library |
| `logs/audit.jsonl` | Written by the engine: one line per decision |

**Its own venv.** The engine does not use the team's `.venv` or `requirements.txt`. `start-mitigation.sh`
creates `mitvenv/` on first run from `requirements-mitigation.txt` (and reinstalls when that file changes),
then links the system Mininet library into it (`system-mininet.pth`), which only the live check needs.
`mitvenv/` is in `.gitignore`. Needs Python 3.7+, `python3-venv`, and internet on the first run.

## 3. Words used in this document

- **Port**: a numbered port on a switch, where a host or another switch is plugged in.
  `{"switch": "of:0000000000000001", "port": "1"}` means switch s1, port 1, where h1 is connected.
- **Edge port**: a port with a host on it. Only edge ports are ever mitigated.
- **Switch-to-switch port**: a port linking two switches (s1:3, s2:3, s2:4, s3:3 in our topology).
  Never mitigated, because it carries traffic for many hosts.
- **Meter**: an OpenFlow rate limit. Here, 2 packets per second; anything above is dropped.
- **Drop rule**: a flow rule with no actions, so every packet that matches it is dropped.
- **tau (τ)**: the anomaly score threshold chosen by the detector. Above τ means "abnormal".
- **Spoofing**: one host sends packets with another host's MAC address, so ONOS believes the
  victim moved to the attacker's port and sends the victim's traffic there (scenario S7).
- **Home port**: the port where the engine first saw a MAC address (it reads ONOS hosts every second).

## 4. How the engine decides

### 4.1 Playbooks (`sentinel/playbooks.yaml`)

| Attack type sent by the detector | Countermeasure on that port | Removed automatically after |
|---|---|---|
| `flood` (S4, S6 pulsed) | Limit to 2 packets/s. If still attacking after 15 s, drop everything from the port | 30 s with score under τ |
| `slow_exhaustion` (S5) | Limit to 2 packets/s | 60 s with score under τ |
| `spoofing` (S7) | Drop only the frames carrying the victim's MAC on the attacker's port | 60 s with score under τ |
| `unknown`, any other type, or confidence under 0.6 | Limit to 2 packets/s and flag for a person (`flag_human`) | never by itself (see 4.2) |

**"Still under attack"** is known in two ways: every repeated `/mitigate` call for the port, and, if τ is known,
`sentinel_anomaly_score` read from the detector's `/metrics` every second. Both reset the "calm" timer.

### 4.2 `unknown` first, then a named type: upgrade
The detector often says `unknown` first, while its window still holds mostly normal traffic, then names the
attack a few seconds later. When a port already has an `unknown` mitigation and an alert with a named type
arrives (`flood`, `slow_exhaustion`, `spoofing`, confidence ≥ 0.6), the engine **removes the unknown rules and
applies the named playbook**. The audit line has `"upgraded_from": "unknown"`. An upgrade is the same incident,
so it is not counted in the 5-per-minute limit. If a spoofing upgrade has no victim to block, the port simply
stays limited (`refused:duplicate`). Any other repeat alert is a duplicate: refused, but it keeps the port "hot".

### 4.3 Re-offenders: no flapping
Without this, a flood would cycle: limited, dropped, calm, released after 30 s, attack resumes, detected again.
If a port is attacked again **within 5 minutes of an automatic release**, the engine:
- goes **straight to the drop** for `flood` and `slow_exhaustion` (no 2 packets/s step), and
- waits **4 times longer** before the next automatic release (2 min for a flood, 4 min for spoofing).

The audit line has `"reoffend": true`. A manual release does not count (a person decided).

### 4.4 Finding the spoofing victim
In this order:
1. **From the detector**: the optional `victim_mac` field. Accepted if ONOS shows that MAC on the attacker's port
   right now, **or** if its home port is another port. (ONOS keeps flipping a victim that keeps talking between
   its real port and the attacker's port, so "right now" alone would often miss it.) A MAC seen nowhere is refused.
2. **From the engine's memory**: a host now on the attacker's port whose home port is elsewhere.
3. **Neither**: the alert falls back to the `unknown` playbook (limit + flag for a person).

The block only drops that one MAC on the attacker's port, so even a wrong value does no more harm than a
false alert on that port would. When the block is removed, the engine also deletes the ONOS `fwd` app's learnt
flows for the victim's MAC (`mac:<MAC>` in `rule_ids`); otherwise the victim stays unreachable.

`pingall` at the start is not required, but it makes every host send traffic, so all home ports are known
before any attack.

### 4.5 Guardrails

| Rule | What happens | Audit `action` |
|---|---|---|
| Never touch a switch-to-switch port (read live from ONOS `/links`) | Refused | `refused:infra_port` |
| ONOS cannot be reached, so links are unknown | Refused (safe default) | `refused:onos_unreachable` |
| One mitigation per port | Refused, except the `unknown` upgrade (4.2) | `refused:duplicate` |
| At most 5 new mitigations per minute | The 6th is refused | `refused:rate_limit` |
| API on `127.0.0.1` only | Not reachable from other machines | |
| Browser requests only from Grafana or the engine's own page | Other websites get HTTP 403 | |
| Every decision is logged | One line in `logs/audit.jsonl`, refusals included | |

## 5. Settings (environment variables, all optional)

Pass them on the command line (`DRY_RUN=1 ./start-mitigation.sh`) or put them in the project's `.env`,
which `start-mitigation.sh` loads.

| Variable | Default | Meaning |
|---|---|---|
| `DRY_RUN` | unset | `1` = decide and log, install nothing in the network |
| `ENGINE_HOST` | `127.0.0.1` | Address the API listens on. Keep the default |
| `ONOS_URL` | `http://127.0.0.1:8181/onos/v1` | ONOS REST API |
| `ONOS_AUTH` | `onos:rocks` | ONOS user:password |
| `SENTINEL_TAU` | read from `models/sentinel_model.joblib` (only if `joblib` and `scikit-learn` are uncommented in `requirements-mitigation.txt`) | Threshold τ |
| `DETECTOR_METRICS` | `http://127.0.0.1:9201/metrics` | Where the engine reads live anomaly scores |
| `GRAFANA_URL` | `http://127.0.0.1:3000` | Where annotations are sent (empty = off) |
| `GRAFANA_TOKEN` | unset | Grafana service-account token for annotations (preferred, see 7.3) |
| `GRAFANA_AUTH` | `admin:admin` | Grafana user:password, used only without a token |
| `ALLOWED_ORIGINS` | unset | Extra comma-separated web origins allowed to POST (e.g. Grafana on another port) |

## 6. API reference

Base URL: `http://127.0.0.1:9202` (from inside the VM). Bodies are JSON.

| Method | Path | Who uses it | What it does |
|---|---|---|---|
| `POST` | `/mitigate` | Detector (Aishwarya) | Report an attack on a port |
| `POST` | `/release` | Operator, Grafana link, demo | Remove the countermeasure from a port |
| `POST` | `/pin` | Operator, demo | Keep a countermeasure (no automatic removal) |
| `GET` | `/status` | Anyone | Active mitigations, JSON |
| `GET` | `/metrics` | Prometheus | Metrics for the dashboard |
| `GET` | `/release` | Operator, Grafana link | Web page: active mitigations with a Release button |

**HTTP status codes**: `200` = handled (also when refused: read `action`), `400` = not JSON or missing
`switch`/`port`, `403` = POST from a web page that is not Grafana or the engine's page, `404` = unknown path.

**Every POST answers** with:
```json
{"action": "meter", "rule_ids": ["meter:1", "flow:49539597560381781"], "dry_run": false}
```
| Field | Meaning |
|---|---|
| `action` | What the engine did (values listed under each endpoint) |
| `rule_ids` | What it installed in ONOS: `flow:<id>`, `meter:<id>`, `mac:<MAC>` (stale flows purged on release) |
| `dry_run` | `true` if the engine runs with `DRY_RUN=1` |

### 6.1 `POST /mitigate`: report an attack

| Field | Type | Required | Meaning |
|---|---|---|---|
| `switch` | string | yes | ONOS device id, e.g. `of:0000000000000001` |
| `port` | string or number | yes | Switch port number, e.g. `"1"` |
| `type` | string | no | `flood`, `slow_exhaustion`, `spoofing`; anything else (or missing) = `unknown` |
| `score` | number | no | Anomaly score (logged) |
| `confidence` | number | no | Attack-type confidence; under 0.6 the type becomes `unknown` |
| `ts` | number | no | Unix time when the alert fired; `installed_ts - alert_ts` in the audit = time to mitigate |
| `victim_mac` | string | no | Spoofing only: the impersonated MAC, e.g. `"00:00:00:00:00:06"` (see 4.4) |

**Call it every second while the port stays abnormal.** Repeats are refused as duplicates but keep the port
"hot", which drives escalation and delays the release. They also carry the upgrade from `unknown` (4.2).

Possible `action` values: `meter`, `drop` (re-offender), `drop_mac`, `meter+flag_human`, `refused:duplicate`,
`refused:infra_port`, `refused:rate_limit`, `refused:onos_unreachable`, `failed` (ONOS rejected a rule;
anything half-installed is removed).

**Examples**

A flood on h1's port:
```bash
curl -s -XPOST localhost:9202/mitigate -d '{"switch":"of:0000000000000001","port":"1","type":"flood","score":0.83,"confidence":0.92,"ts":1794758323.9}'
```
```json
{"action": "meter", "rule_ids": ["meter:1", "flow:49539597560381781"], "dry_run": false}
```

The detector is not sure yet, then names a spoofing attack and its victim (h3's port impersonating h6):
```bash
curl -s -XPOST localhost:9202/mitigate -d '{"switch":"of:0000000000000001","port":"2","type":"unknown","score":0.71,"confidence":0.4}'
```
```json
{"action": "meter+flag_human", "rule_ids": ["meter:1", "flow:49539597551299332"], "dry_run": false}
```
```bash
curl -s -XPOST localhost:9202/mitigate -d '{"switch":"of:0000000000000001","port":"2","type":"spoofing","score":0.91,"confidence":0.88,"victim_mac":"00:00:00:00:00:06"}'
```
```json
{"action": "drop_mac", "rule_ids": ["flow:49539597683243734", "mac:00:00:00:00:00:06"], "dry_run": false}
```

A switch-to-switch port is refused:
```bash
curl -s -XPOST localhost:9202/mitigate -d '{"switch":"of:0000000000000001","port":"3","type":"flood","confidence":0.9}'
```
```json
{"action": "refused:infra_port", "rule_ids": [], "dry_run": false}
```

From Python, the detector side (`requests` is in the team's `requirements.txt`):
```python
import time, requests

ENGINE = "http://127.0.0.1:9202"

def report(switch, port, attack_type, score, confidence, victim_mac=None):
    alert = {"switch": switch, "port": str(port), "type": attack_type,
             "score": score, "confidence": confidence, "ts": time.time()}
    if victim_mac:                      # spoofing only
        alert["victim_mac"] = victim_mac
    try:
        return requests.post(ENGINE + "/mitigate", json=alert, timeout=2).json()
    except requests.RequestException as e:
        print("engine unreachable:", e)  # never let the detector crash because of the engine

report("of:0000000000000001", 1, "flood", 0.83, 0.92)
```

### 6.2 `POST /release`: remove the countermeasure from a port

```bash
curl -s -XPOST localhost:9202/release -d '{"switch":"of:0000000000000001","port":"1"}'
```
```json
{"action": "release:manual", "rule_ids": ["meter:1", "flow:49539597560381781"], "dry_run": false}
```
`action`: `release:manual`, or `refused:not_active` if nothing is active on that port.
In the audit log, automatic removals appear as `release:auto` and removals at Ctrl-C as `release:shutdown`.

### 6.3 `POST /pin`: keep a countermeasure

```bash
curl -s -XPOST localhost:9202/pin -d '{"switch":"of:0000000000000001","port":"1"}'
```
```json
{"action": "pin", "rule_ids": ["meter:1", "flow:49539597560381781"], "dry_run": false}
```
`action`: `pin`, or `refused:not_active`. A pinned mitigation is never removed automatically; `/release` removes it.

### 6.4 `GET /status`: what is active right now

```bash
curl -s localhost:9202/status
```
```json
{"of:0000000000000001 1": {"type": "flood", "action": "drop", "rules": ["meter:1", "flow:4953...", "flow:4953..."],
  "started": 1794758324.2, "last_hot": 1794758339.4, "escalated": true, "pinned": false,
  "reoffend": false, "score": 0.83, "confidence": 0.92}}
```
Keys are `"<switch> <port>"`. `action` = the current countermeasure (`drop` once a flood escalated),
`last_hot` = last time the port was seen under attack, `reoffend` = see 4.3. `{}` when nothing is active.

### 6.5 `GET /metrics`: for Prometheus and Grafana

```bash
curl -s localhost:9202/metrics
```
```
# TYPE sentinel_mitigation_active gauge
sentinel_mitigation_active{switch="of:0000000000000001",port="2"} 1
# TYPE sentinel_actions_total counter
sentinel_actions_total{switch="of:0000000000000001",port="2"} 1
# TYPE sentinel_flag_human gauge
sentinel_flag_human{switch="of:0000000000000001",port="2"} 1
# TYPE sentinel_mitigation_info gauge
sentinel_mitigation_info{switch="of:0000000000000001",port="2",type="unknown",action="meter+flag_human",pinned="0",reoffend="0",flag_human="1"} 1
```

| Metric | Meaning |
|---|---|
| `sentinel_mitigation_active` | 1 while the port is mitigated, 0 after release (shared contract) |
| `sentinel_actions_total` | Actions taken on the port: installs, escalations, upgrades (shared contract) |
| `sentinel_flag_human` | 1 while the port waits for a person (the `unknown` playbook) |
| `sentinel_mitigation_info` | One series per active mitigation, details as labels: for a Grafana table |

### 6.6 `GET /release`: the operator page

Open **http://localhost:9202/release** in the VM's browser: a table of the active mitigations (switch, port,
type, action, how long, pinned) with a **Release** button on each row. Waiting-for-a-person rows are in red.
`http://localhost:9202/release?switch=of:0000000000000001&port=2` shows only that port; this is what the
Grafana link opens (section 7.2). The page itself changes nothing: only the button does, with a `POST /release`.

### 6.7 Audit log: `logs/audit.jsonl`

One JSON object per line, one line per decision (refusals included):
```json
{"ts": 1794766919.16, "switch": "of:0000000000000001", "port": "2", "type": "spoofing", "score": 0.91,
 "confidence": 0.88, "action": "drop_mac", "onos_status": "ok",
 "rule_ids": ["flow:49539597683243734", "mac:00:00:00:00:00:06"], "dry_run": false,
 "upgraded_from": "unknown", "installed_ts": 1794766919.16, "alert_ts": 1794766919.13,
 "victim_mac": "00:00:00:00:00:06"}
```
| Field | When | Meaning |
|---|---|---|
| `ts`, `switch`, `port`, `type`, `score`, `confidence`, `action`, `onos_status`, `rule_ids` | always | shared contract |
| `dry_run` | always | the engine runs with `DRY_RUN=1` |
| `alert_ts`, `installed_ts` | new mitigations | `installed_ts - alert_ts` = time to mitigate |
| `victim_mac` | alert carried one | what the detector claimed (the MAC actually blocked is the `mac:` entry in `rule_ids`) |
| `upgraded_from` | upgrade (4.2) | always `"unknown"` |
| `reoffend` | re-offender (4.3) | `true` |

`onos_status`: `ok`, `dry_run`, `skipped` (nothing sent to ONOS, e.g. a refusal) or `error: ...`.
Escalations are logged with `action: "drop"`.

## 7. Grafana dashboard

### 7.1 Data
Prometheus already scrapes the engine every second (`monitoring/prometheus.yml`, job `engine`, `localhost:9202`).
Useful queries:

| Panel | PromQL |
|---|---|
| Active mitigations (table) | `sentinel_mitigation_info` |
| Number of mitigated ports (stat) | `sum(sentinel_mitigation_active)` |
| Ports waiting for a person (stat, red when > 0) | `sum(sentinel_flag_human)` |
| Actions per minute (time series) | `sum(increase(sentinel_actions_total[1m]))` |

### 7.2 Table of running mitigations with a Release link
Add a **Table** panel, query `sentinel_mitigation_info`, **Format: Table**, **Type: Instant**. Then:
1. Transform **Organize fields**: hide `Time`, `Value`, `__name__`, `job`, `instance`.
2. Override for the field `port`: **Data links → Add link**, title `Release`, URL
   ```
   http://localhost:9202/release?switch=${__data.fields.switch}&port=${__data.fields.port}
   ```
   and tick **Open in new tab**.

Clicking a port opens the engine's page for that port, with a **Release** button. The release itself happens
there (a `POST`), so a stray click or a link preview can't remove a mitigation.

Panel JSON to paste (Dashboard → Add → Import panel, or into the dashboard JSON):
```json
{
  "type": "table",
  "title": "Active mitigations",
  "datasource": {"type": "prometheus", "uid": "prometheus"},
  "targets": [{"refId": "A", "expr": "sentinel_mitigation_info", "format": "table", "instant": true}],
  "transformations": [{"id": "organize", "options": {"excludeByName":
    {"Time": true, "Value": true, "__name__": true, "job": true, "instance": true}}}],
  "fieldConfig": {"defaults": {}, "overrides": [{"matcher": {"id": "byName", "options": "port"},
    "properties": [{"id": "links", "value": [{"title": "Release", "targetBlank": true,
      "url": "http://localhost:9202/release?switch=${__data.fields.switch}&port=${__data.fields.port}"}]}]}]}
}
```
The link works for a browser running in the VM (Grafana and the engine are both on localhost).

### 7.3 Annotations (a marker on the graphs at every action)
After every action the engine calls Grafana's `POST /api/annotations` with tags `sentinel` and the action.
1. Create a token: Grafana → **Administration → Users and access → Service accounts → Add service account**
   (role **Editor**) → **Add service account token**.
2. Put it in the project's `.env`: `GRAFANA_TOKEN=glsa_...` (`start-mitigation.sh` loads `.env`).
3. In the dashboard: **Settings → Annotations → New**, data source **Grafana**, filter by **Tags**, tag `sentinel`.

Without a token the engine logs in with `GRAFANA_AUTH` (default `admin:admin`), which fails if the admin
password was changed in `.env`. Failures are ignored: the mitigation never waits for Grafana.

## 8. For the other parts of the project

**Detector (Aishwarya)**
- Call `POST /mitigate` (6.1) after 3 windows above τ, then **every second** while the port stays above τ.
- Sending `unknown` first is fine; the named type upgrades it (4.2).
- For spoofing, add `victim_mac` (the MAC that showed up away from its home port).
- Optional: expose `sentinel_anomaly_score{switch,port}` on `:9201/metrics` and give the engine τ
  (`SENTINEL_TAU`), so it also sees the score itself.

**Dashboard (Nkwenti)**
- Panels and queries: 7.1 and 7.2. Annotations: 7.3. New metrics: `sentinel_flag_human`, `sentinel_mitigation_info`.
- Timing table: `installed_ts - alert_ts` in `logs/audit.jsonl`; release times from `release:auto` lines.

**Testbed (Ilias)**
- During a joint test, run the engine with `DRY_RUN=1` first: the audit log shows the action chosen for each alert.

## 9. Testing

```bash
./start-mitigation.sh test
```
About 2 seconds, fake ONOS: playbooks, guardrails, upgrade, re-offender, victim rules, metrics, the HTTP API
(release page, origin check), Grafana token and the dry run. Prints `ok`.

```bash
./start-mitigation.sh live-check
```
The real test, about 4 minutes. ONOS must be up and **no other Mininet running** (the script starts its own
topology). It runs every "Expected results" row of the project plan plus the scenarios in section 4
(no-history spoofing, `unknown` then `spoofing` while ONOS flips the victim back, `unknown` then `flood`,
a real re-offender, the release page) and prints `40/40 passed`. Its audit lines go to
`logs/live_check_audit.jsonl` so the real audit log stays clean. It asks for sudo because Mininet needs root;
the engine it starts runs as your own user.

### Checking by hand
With the engine and the topology running (section 1), from another terminal:
1. **Rule installed fast:** send the flood example from 6.1, then look at the switch. A `meter=1` line and a
   flow with `priority=49000,in_port=1` appear at once.
   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-meters s1
   ```
   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1
   ```
2. **Meter drops traffic:** while h1 sends (`h1 ping -i 0.1 h2` in Mininet), the band `packet_count` grows.
   ```bash
   sudo ovs-ofctl -O OpenFlow13 meter-stats s1
   ```
3. **Clean rollback:** release the port (6.2); Sentinel flows use priorities 49000, 50000, 51000, so this
   must print nothing:
   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -E 'priority=(49000|50000|51000)'
   ```
4. **Guardrails:** each refusal appears as `refused:...`:
   ```bash
   tail -n 5 logs/audit.jsonl
   ```

If the engine ever crashes and leaves rules behind, this removes every rule installed through the REST API:
```bash
curl -u onos:rocks -XDELETE http://127.0.0.1:8181/onos/v1/flows/application/org.onosproject.rest
```

## 10. Known limitations

- The engine remembers where each host was first seen and never updates it. A host that is legitimately
  moved to another port would look like a spoofing victim there.
- If neither the detector (`victim_mac`) nor the engine's memory can name the victim, a spoofing alert is
  handled by the `unknown` playbook: the port is limited and flagged, which slows the impersonation but does
  not fully stop it.
- An impostor whose frames match flows already cached in the switch stays invisible to ONOS until those flows
  expire (about 10 s idle), so detection based on ONOS host moves can lag.
- A false `unknown` on an innocent port stays limited until a person releases it; `sentinel_flag_human` and
  the red rows on the release page are there so it is noticed.
