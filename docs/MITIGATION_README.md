# Sentinel mitigation engine

The mitigation engine is the part of Sentinel that **reacts** to an attack. The detector tells it
"switch X, port Y is under attack of type Z", and the engine puts a countermeasure on that one
switch port through ONOS. It logs every decision and removes the countermeasure once the attack is over.

It is a small HTTP API server (JSON, port **9202**) written with the Python standard library.

## 1. Files

| File | What it is |
|---|---|
| `sentinel/engine.py` | The API server: decisions, guardrails, rollback, metrics, audit log |
| `sentinel/onos_client.py` | Talks to the ONOS REST API (meters, flow rules, links, hosts) |
| `sentinel/playbooks.yaml` | Which countermeasure to use for each attack type |
| `sentinel/test_engine.py` | Quick offline test with a fake ONOS (no network needed) |
| `sentinel/live_check.py` | Full test against the real ONOS and Mininet |
| `logs/audit.jsonl` | Written by the engine: one line per decision |
| `start-mitigation.sh` | Starts the engine (or its tests) in its own venv, `mitvenv/` |
| `requirements-mitigation.txt` | What `mitvenv/` contains: only PyYAML; the rest is the standard library |

**Its own venv.** The engine does not use the team's `.venv` or `requirements.txt`. `start-mitigation.sh`
creates `mitvenv/` on first run from `requirements-mitigation.txt` (and reinstalls when that file changes),
then links the system Mininet library into it with `system-mininet.pth`, which only the live check needs.
`mitvenv/` is in `.gitignore`. Needs Python 3.7+, `python3-venv`, and internet on the first run.

## 2. Words used in this document

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

## 3. How to start it (in the VM, from the project folder)

1. ONOS must be running. Start it once after a reboot:
   ```bash
   docker compose up -d
   ```
2. Start the topology in its own terminal, then type `pingall` at the `mininet>` prompt:
   ```bash
   sudo mn -c && sudo python3 topo/lab_topo.py --link-s3
   ```
3. Start the engine in another terminal (the first run also creates `mitvenv/`):
   ```bash
   ./start-mitigation.sh
   ```
   It prints `sentinel engine on :9202  dry_run=False  tau=...  hosts_known=...`.
4. Stop it with **Ctrl-C**. It removes every rule it installed before exiting.

Test mode, where the engine decides and writes the audit log but installs nothing in the network:
```bash
DRY_RUN=1 ./start-mitigation.sh
```
Settings from the table below are passed the same way, e.g. `SENTINEL_TAU=0.6 ./start-mitigation.sh`.

**About `pingall` and host learning.** For a spoofing alert the engine needs to know the victim's MAC.
It gets it in one of two ways, in this order:
1. **From the detector**: the optional `victim_mac` field of `/mitigate` (see section 6). The engine uses it
   only if ONOS really shows that MAC on the attacker's port, so a wrong value can't get another host blocked.
2. **From its own memory**: the engine reads the host list from ONOS every second and remembers where each
   host was **first** seen. A host now on the attacker's port that was first seen elsewhere is the victim.

`pingall` is not required, but it makes every host send traffic so all of them are learnt before any attack.
The engine can be started before or after `pingall`. If neither way names a victim, the engine falls back
to the "unknown" playbook (limit the port and flag it for a person).

### Settings (environment variables, all optional)

| Variable | Default | Meaning |
|---|---|---|
| `DRY_RUN` | unset | `1` = decide and log, install nothing |
| `ONOS_URL` | `http://127.0.0.1:8181/onos/v1` | ONOS REST API |
| `ONOS_AUTH` | `onos:rocks` | ONOS user:password |
| `SENTINEL_TAU` | read from `models/sentinel_model.joblib`, only if `joblib` and `scikit-learn` are uncommented in `requirements-mitigation.txt` | Threshold τ, set by hand |
| `DETECTOR_METRICS` | `http://127.0.0.1:9201/metrics` | Where the engine reads live anomaly scores |
| `GRAFANA_URL` | `http://127.0.0.1:3000` | Where action annotations are sent (empty = off) |
| `GRAFANA_AUTH` | `admin:admin` | Grafana user:password |

## 4. What the engine does for each attack (`playbooks.yaml`)

| Attack type sent by the detector | Countermeasure on that port | Removed automatically after |
|---|---|---|
| `flood` (S4, S6 pulsed) | Limit to 2 packets/s. If still attacking after 15 s, drop everything from the port | 30 s with score under τ |
| `slow_exhaustion` (S5) | Limit to 2 packets/s | 60 s with score under τ |
| `spoofing` (S7) | Drop only the frames carrying the victim's MAC on the attacker's port | 60 s with score under τ |
| anything else, or confidence under 0.6 | Limit to 2 packets/s and flag for a person | never; a person calls `/release` |

**How the engine knows an attack is still going**, which drives both escalation and automatic removal:
- every `/mitigate` call for a port that is already mitigated counts as "still under attack", and
- if τ is known, the engine also reads `sentinel_anomaly_score` from the detector's `/metrics` every second.

**When a spoofing block is removed**, the engine also deletes the ONOS `fwd` app's learnt flows for
the victim's MAC (listed as `mac:<MAC>` in `rule_ids`). Without that, those old flows keep sending the
victim's traffic to the attacker's port, and the victim stays unreachable.

## 5. Guardrails (safety rules)

| Rule | What happens | Audit `action` |
|---|---|---|
| Never touch a switch-to-switch port (read live from ONOS `/links`) | Refused | `refused:infra_port` |
| ONOS cannot be reached, so links are unknown | Refused (safe default) | `refused:onos_unreachable` |
| One mitigation per port | A second alert on the same port is refused (but still counts as "still attacking") | `refused:duplicate` |
| At most 5 new mitigations per minute | The 6th is refused | `refused:rate_limit` |
| Every decision is logged | One line in `logs/audit.jsonl`, refusals included | |

## 6. API documentation

Base URL: `http://127.0.0.1:9202` (from inside the VM).
Requests and responses are JSON. Every `POST` needs `switch` and `port`.

### Common response for POST endpoints

```json
{"action": "meter", "rule_ids": ["meter:1", "flow:49539597560381781"], "dry_run": false}
```

| Field | Meaning |
|---|---|
| `action` | What the engine did (see the list of values below) |
| `rule_ids` | What it installed in ONOS: `flow:<id>`, `meter:<id>`, `mac:<MAC>` (stale flows purged on release) |
| `dry_run` | `true` if the engine runs with `DRY_RUN=1` (nothing installed) |

HTTP status codes: `200` = request handled (also when refused; read `action`),
`400` = invalid JSON or missing `switch`/`port`, `404` = unknown path.

### `POST /mitigate`: an alert from the detector

Request:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `switch` | string | yes | ONOS device id, e.g. `of:0000000000000001` |
| `port` | string or number | yes | Switch port number, e.g. `"1"` |
| `type` | string | no | `flood`, `slow_exhaustion`, `spoofing`; anything else is treated as `unknown` |
| `score` | number | no | Anomaly score |
| `confidence` | number | no | Attack-type confidence; under 0.6 the type becomes `unknown` |
| `ts` | number | no | Unix time when the alert fired (used for the timing table) |
| `victim_mac` | string | no | Spoofing only: the MAC being impersonated, e.g. `"00:00:00:00:00:06"`. Used only if ONOS shows that MAC on this port right now; otherwise ignored and the engine uses its own memory. Copied into the audit line |

Example:
```bash
curl -s -XPOST localhost:9202/mitigate -d '{"switch":"of:0000000000000001","port":"1","type":"flood","score":0.83,"confidence":0.92,"ts":1794758323.9}'
```
From Python (detector side):
```python
requests.post("http://127.0.0.1:9202/mitigate", json={"switch": sw, "port": port, "type": typ,
              "score": score, "confidence": conf, "ts": time.time()}, timeout=2)
```
Spoofing alert where the detector names the victim:
```bash
curl -s -XPOST localhost:9202/mitigate -d '{"switch":"of:0000000000000001","port":"2","type":"spoofing","score":0.91,"confidence":0.88,"victim_mac":"00:00:00:00:00:06"}'
```
Send it again every second while the port stays abnormal. Repeats are refused as duplicates, but they
tell the engine the attack is still going.

Possible `action` values: `meter`, `drop_mac`, `meter+flag_human`, `refused:duplicate`,
`refused:infra_port`, `refused:rate_limit`, `refused:onos_unreachable`, `failed` (ONOS rejected a rule;
anything half-installed is removed).

### `POST /release`: remove the countermeasure from a port

```bash
curl -s -XPOST localhost:9202/release -d '{"switch":"of:0000000000000001","port":"1"}'
```
Response `action`: `release:manual`, or `refused:not_active` if nothing is active on that port.
(Automatic removals are logged as `release:auto`, removals at Ctrl-C as `release:shutdown`.)

### `POST /pin`: keep a countermeasure (no automatic removal)

```bash
curl -s -XPOST localhost:9202/pin -d '{"switch":"of:0000000000000001","port":"1"}'
```
Response `action`: `pin`, or `refused:not_active`. To undo a pin, call `/release`.

### `GET /status`: what is active right now

```bash
curl -s localhost:9202/status
```
```json
{"of:0000000000000001 1": {"type": "flood", "rules": ["meter:1", "flow:4953..."], "started": 1794758324.2,
  "last_hot": 1794758339.4, "escalated": true, "pinned": false, "score": 1.0, "confidence": 0.9}}
```
`last_hot` = last time the port was seen under attack; `escalated` = the flood was upgraded to a full drop.

### `GET /metrics`: Prometheus metrics (scraped by Prometheus)

```
# TYPE sentinel_mitigation_active gauge
sentinel_mitigation_active{switch="of:0000000000000001",port="1"} 1
# TYPE sentinel_actions_total counter
sentinel_actions_total{switch="of:0000000000000001",port="1"} 2
```
`sentinel_mitigation_active` is 1 while a port is mitigated, 0 after release.
`sentinel_actions_total` counts the actions taken on a port (install and escalation).

### Audit log: `logs/audit.jsonl`

One JSON object per line, one line per decision (refusals included):
```json
{"ts": 1794758324.27, "switch": "of:0000000000000001", "port": "1", "type": "flood", "score": 1.0,
 "confidence": 0.9, "action": "meter", "onos_status": "ok", "rule_ids": ["meter:1", "flow:4953..."],
 "dry_run": false, "alert_ts": 1794758323.96, "installed_ts": 1794758324.27}
```
`onos_status`: `ok`, `dry_run`, `skipped` (nothing sent to ONOS, e.g. a refusal) or `error: ...`.
Escalations are logged with `action: "drop"`. `installed_ts - alert_ts` = time to mitigate.
When the alert carried a `victim_mac`, it is copied into the line as `victim_mac`. The victim that was
actually blocked is the `mac:<MAC>` entry in `rule_ids`; if there is none, the hint was not used.

Every action except refusals is also sent to Grafana as an annotation (tag `sentinel`).

## 7. Testing

```bash
./start-mitigation.sh test
```
Runs in about a second with a fake ONOS and checks the playbooks, guardrails and rollback logic. Prints `ok`.

```bash
./start-mitigation.sh live-check
```
The real test, about 2 minutes. ONOS must be up and **no other Mininet running**, because the script starts
its own topology. It goes through every "Expected results" row of the project plan, plus spoofing with no
prior knowledge (engine restarted while h6 is already hijacked, with and without `victim_mac`), and prints `26/26 passed`.
Its audit lines go to `logs/live_check_audit.jsonl` so the real audit log stays clean.
It asks for sudo because Mininet needs root; the engine it starts runs as your own user.

### Checking by hand, step by step

Run the engine and the topology as in section 3, then from another terminal:

1. **Is the rule installed fast?** Send a fake flood alert for h1's port, then look at the switch.
   A `meter=1` line and a flow with `priority=49000,in_port=1` should appear at once.
   ```bash
   curl -s -XPOST localhost:9202/mitigate -d '{"switch":"of:0000000000000001","port":"1","type":"flood","score":1,"confidence":0.9}'
   ```
   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-meters s1
   ```
   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1
   ```
2. **Does the meter really drop traffic?** While h1 sends traffic (e.g. `h1 ping -i 0.1 h2` in Mininet),
   the band `packet_count` (packets dropped by the meter) keeps increasing.
   ```bash
   sudo ovs-ofctl -O OpenFlow13 meter-stats s1
   ```
3. **Is the rollback clean?** Release the port; afterwards no Sentinel flow is left
   (Sentinel flows use priorities 49000, 50000, 51000, so this command must print nothing).
   ```bash
   curl -s -XPOST localhost:9202/release -d '{"switch":"of:0000000000000001","port":"1"}'
   ```
   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -E 'priority=(49000|50000|51000)'
   ```
4. **Do the guardrails hold?** Send an alert for s1 port 3 (link to s2), then the same alert twice, then
   alerts on 6 different edge ports within a minute. Each refusal appears in the log as `refused:...`.
   ```bash
   tail -n 5 logs/audit.jsonl
   ```
5. **What is the engine doing right now?**
   ```bash
   curl -s localhost:9202/status
   ```
   ```bash
   curl -s localhost:9202/metrics
   ```

If the engine ever crashes and leaves rules behind, this removes every rule installed through the REST API:
```bash
curl -u onos:rocks -XDELETE http://127.0.0.1:8181/onos/v1/flows/application/org.onosproject.rest
```

## 8. Known limitations

- The engine remembers where each host was first seen and never updates it. A host that is legitimately
  moved to another port would look like a spoofing victim there; this only matters if a spoofing alert
  then fires on that new port and the detector sends no `victim_mac`.
- If neither the detector (`victim_mac`) nor the engine's memory can name the victim, the spoofing alert is
  handled by the "unknown" playbook: the port is limited to 2 packets/s and flagged for a person, which slows
  the impersonation but does not fully stop it.
