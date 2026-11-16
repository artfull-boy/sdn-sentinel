# Monitoring

## Contents

1. [Architecture](#architecture)
2. [Requirements](#requirements)
3. [Quick start](#quick-start)
4. [Step-by-step setup](#step-by-step-setup)
5. [Check that everything works](#check-that-everything-works)
6. [Dashboard and evaluation](#dashboard-and-evaluation)
7. [Repository layout](#repository-layout)
8. [Shared contracts](#shared-contracts)
9. [Data and model training (Google Colab)](#data-and-model-training-google-colab)
10. [How we work with Git](#how-we-work-with-git)
11. [Troubleshooting](#troubleshooting)
12. [What never goes in this repo](#what-never-goes-in-this-repo)

---

## Architecture

![Sentinel architecture](docs/sentinel_architecture.png)

1. Open vSwitch switches (in Mininet) talk to ONOS over OpenFlow 1.3.
2. The **collector** polls the ONOS REST API every second and computes 12 features per edge port.
3. The **ML detector** scores each port: an Isolation Forest (unsupervised, trained on normal
   traffic only) decides whether the port is abnormal, then a Random Forest (supervised) names the
   attack type.
4. The **mitigation engine** receives the alert and the attack type.
5. The engine installs the countermeasure through ONOS REST (an OpenFlow meter or a drop rule)
   and removes it after recovery.

Prometheus and Grafana only observe; they are not in the decision path. The model is trained
offline in Google Colab and copied into `models/`.

---

## Requirements

| What | Version we use | Notes |
| --- | --- | --- |
| VM | Kali Linux (Ubuntu 22.04 or Debian also work) | 4 vCPU and 8 GB RAM or more recommended |
| Mininet | 2.3.x | Installed by `setup.sh` |
| Open vSwitch | from the distribution | Switches run on the **userspace datapath** so meters work |
| Docker + Docker Compose | recent | ONOS, Prometheus and Grafana run in containers |
| ONOS | **2.7.0** (`onosproject/onos:2.7.0`) | Same image for everyone |
| Python | 3.10 or newer | Packages pinned in `requirements.txt` |

---

## Quick start

For teammates who just want it running:

```bash
git clone https://github.com/artfull-boy/sdn-sentinel.git
cd sdn-sentinel
./setup.sh                        # once per VM
cp .env.example .env              # then edit the passwords in .env
docker compose up -d              # ONOS, Prometheus, Grafana
# wait about 1 to 2 minutes for ONOS to start
sudo python3 topo/lab_topo.py --link-s3
mininet> pingall                  # expect 0% dropped
```

---

## Step-by-step setup

### 1. Install the tools

```bash
./setup.sh
```

The script installs Mininet, Open vSwitch, Docker, Git and a Python virtual environment with the
packages from `requirements.txt`. It also adds you to the `docker` group, so **log out and log
back in once** (or run `newgrp docker`) before using Docker without `sudo`.

Check the install:

```bash
sudo mn --version
docker compose version
```

### 2. Configure secrets

```bash
cp .env.example .env
nano .env        # set GF_SECURITY_ADMIN_PASSWORD and, later, GRAFANA_TOKEN
```

`.env` is ignored by Git. Never commit it.

### 3. Start ONOS, Prometheus and Grafana

```bash
docker compose up -d
docker logs -f onos              # wait until ONOS finishes starting, then Ctrl+C
```

ONOS starts with the apps `drivers`, `openflow` and `fwd` already activated (set by
`ONOS_APPS` in `docker-compose.yml`). The GUI, REST API and Karaf SSH are bound to `127.0.0.1`
only, as in our Lab 2 hardening. The OpenFlow port `6653` stays open for the switches.

| Service | Address | Login |
| --- | --- | --- |
| ONOS GUI | http://localhost:8181/onos/ui | `onos` / `rocks` |
| ONOS REST API | http://localhost:8181/onos/v1/ | `onos` / `rocks` |
| ONOS CLI (Karaf) | `ssh -p 8101 onos@localhost` | password `rocks` |
| Prometheus | http://localhost:9090 | none |
| Grafana | http://localhost:3000 | `admin` / password from `.env` |

### 4. Start the topology

```bash
sudo mn -c                                  # clean any old run first
sudo python3 topo/lab_topo.py --link-s3
```

The topology has 6 hosts and 3 switches. The switches use `datapath="user"` and connect to the
controller at `127.0.0.1:6653`.

| Host | IP | Switch:port | Role in the project |
| --- | --- | --- | --- |
| h1 | 10.0.1.1 | s1:1 | attacker |
| h3 | 10.0.2.1 | s1:2 | |
| h2 | 10.0.1.2 | s2:1 | |
| h4 | 10.0.2.2 | s2:2 | second attacker (optional scenario S8) |
| h5 | 10.0.3.1 | s3:1 | |
| h6 | 10.0.3.2 | s3:2 | target |

### 5. Start the Sentinel services

These are being built during the project; the commands below are the agreed entry points.

```bash
. .venv/bin/activate
python -m sentinel.collector                 # :9200  live mode
python -m sentinel.collector --record data/raw/run_01.csv   # record mode
python -m sentinel.detector                  # :9201  needs models/sentinel_model.joblib
DRY_RUN=1 python -m sentinel.engine          # :9202  logs decisions, installs nothing
python -m sentinel.engine                    # :9202  real mitigation
```

---

## Check that everything works

Run these after every fresh setup:

```bash
# 1. ONOS sees the 3 switches
curl -s -u onos:rocks http://localhost:8181/onos/v1/devices | python3 -m json.tool | grep '"id"'

# 2. In Mininet: full connectivity
mininet> pingall                             # 0% dropped

# 3. Flow table settles back to about 74 rules after pingall (Lab 2 baseline)
curl -s -u onos:rocks http://localhost:8181/onos/v1/flows | python3 -c "import sys,json; print(len(json.load(sys.stdin)['flows']))"

# 4. The switches can run meters (userspace datapath)
sudo ovs-ofctl -O OpenFlow13 dump-meters s1  # no OFPMMFC_INVALID_METER error

# 5. Prometheus sees its targets
# open http://localhost:9090/targets
# expected targets: collector, detector and engine are UP while those services run
```

---

## Dashboard and evaluation

Grafana provisions the `Sentinel` dashboard from
`monitoring/grafana/provisioning/dashboards/sentinel_v1.json`. It includes the
flow-table reference (74), the 30-new-flows/s baseline, the rule firing state,
anomaly score and threshold, detected attack type, active mitigations, and
ML-versus-rule and action timelines. The dashboard refreshes every five seconds.
The Prometheus scrape targets use `127.0.0.1`; reload/restart Prometheus after
changing the configuration.

The detector and engine must expose the shared Prometheus metrics below. The
dashboard uses two additive metric details so it can draw the model threshold
and show the attack type:

- `sentinel_anomaly_threshold`: current model threshold as a gauge.
- `sentinel_attack_type`: one-hot gauge with labels `{switch, port, type}`.
  Use the finite `type` values `normal`, `flood`, `slow_exhaustion`, and
  `spoofing`; set the current type to `1` and other types to `0`. The dashboard
  excludes `type="normal"` from its attack timeline and detection line.
- Include an `action` label on `sentinel_actions_total` so action annotations
  and counts can be grouped.

These are additive to the shared metrics contract below. Until teammates export
them, their dashboard panels will have no corresponding live series.

Generate evaluation tables from saved run labels and audit records:

```bash
python3 eval/evaluate.py \
  --labels data/labels.jsonl \
  --audit logs/audit.jsonl \
  --rule-samples results/rule_samples.csv \
  --ping-log results/s10_ping.csv \
  --output-dir results
```

`--rule-samples` accepts either `ts,rule_fired` samples exported from
`sentinel:rule_baseline:fired`, or `ts,new_flows` samples. For flow samples,
provide per-switch samples that the script can sum by timestamp; it applies the
rule's three-consecutive-seconds threshold of over 30 new flows/s. The run's
attack window comes from `t_start` and `t_end` in `labels.jsonl`.

The audit input is one JSON object per line using the agreed `ts`, `switch`,
`port`, `type`, `action`, and `onos_status` fields. The evaluator reports the
first matching detection and successful mitigation during the labelled attack,
and the first successful release after its end. Ping input is CSV with
`run_id,ts,success,latency_ms` columns; `success` may be `1`/`true` or
`0`/`false`. Only successful probes with a latency contribute to latency
statistics.

The script writes `ml_vs_rule.csv`, `timing.csv`, and per-scenario median
`timing_summary.csv`, plus `collateral_damage.csv` when ping logs are supplied.
Without rule samples the rule result is marked unavailable, not a miss; without
ping logs no collateral-damage table is created. These are measurements from
the supplied logs, not inferred or fabricated results. The 74-flow figure is a
dashboard reference, not a pass/fail assertion for every run.

---

## Repository layout

```
sdn-sentinel/
├── README.md
├── setup.sh                  # installs everything on a fresh VM
├── docker-compose.yml        # ONOS 2.7.0, Prometheus, Grafana
├── requirements.txt          # pinned Python packages
├── .env.example              # copy to .env, never commit .env
├── .gitignore
├── docs/                     # architecture diagram, report figures
├── topo/
│   └── lab_topo.py           # 6 hosts, 3 switches, datapath="user"
├── scenarios/
│   ├── traffic_gen.py        # idle, pingall, iperf, mixed
│   ├── run_scenario.py       # runs a scenario and writes data/labels.jsonl
│   └── attacks/              # flood, slow flood, pulsed flood, spoofing
├── sentinel/
│   ├── features.py           # the ONE feature module (record and live)
│   ├── collector.py          # :9200
│   ├── detector.py           # :9201
│   ├── onos_client.py        # meters, flows, drop rules, rollback
│   ├── engine.py             # :9202 playbooks, guardrails, audit log
│   └── playbooks.yaml
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/              # provisioning and dashboard JSON
├── eval/
│   └── evaluate.py           # reproducible ML/rule, timing and ping tables
├── notebooks/                # 00 to 03, saved from Google Colab
├── models/                   # sentinel_model.joblib (not committed)
├── data/                     # recordings (not committed)
└── logs/                     # audit.jsonl (not committed)
```

---

## Shared contracts

Change these only after telling the whole group.

**Ports:** collector `9200`, detector `9201`, engine `9202`, Prometheus `9090`, Grafana `3000`,
ONOS REST `8181`, ONOS CLI `8101`, OpenFlow `6653`.

**Feature names** (one row per edge port per second, 10 s window):

```
new_flows, new_flows_max_1s, burstiness, active_secs, uniq_src_mac, uniq_dst_mac,
rx_pkts, flows_per_pkt, hosts_on_port, host_moves_in, table_size_sw, table_growth
```

**Feature CSV columns:** `ts, run_id, switch, port,` the 12 features, `label, split`

**Labels:** `normal`, `flood` (includes pulsed), `slow_exhaustion`, `spoofing`

**`data/labels.jsonl`** (one line per run):

```json
{"run_id": "flood_03", "scenario": "S4", "label": "flood",
 "attacker": "of:0000000000000001:1", "t_start": 1763030400, "t_end": 1763030460}
```

**Engine API:**

```
POST /mitigate   {"switch", "port", "type", "score", "confidence", "ts"}
                 -> {"action", "rule_ids", "dry_run"}
POST /release    {"switch", "port"}
POST /pin        {"switch", "port"}
```

**Prometheus metrics** (labels `{switch, port}`): `sentinel_new_flows`,
`sentinel_anomaly_score`, `sentinel_attack_type`, `sentinel_mitigation_active`,
`sentinel_actions_total`

For the Grafana dashboard, `sentinel_anomaly_threshold` reports the active
model threshold, `sentinel_attack_type` uses an additional `type` label and a
one-hot gauge value (`normal`, `flood`, `slow_exhaustion`, or `spoofing`), and
`sentinel_actions_total` includes an `action` label.

**Model file:** `models/sentinel_model.joblib` with keys
`iforest, tau, k, rf, min_conf, features, sklearn`

---

## Data and model training (Google Colab)

1. Record runs on the VM with the collector in record mode and `scenarios/run_scenario.py`.
2. Upload `data/raw/*.csv` and `data/labels.jsonl` to the shared Google Drive folder
   `MyDrive/sdn-sentinel/data/` (link: `<shared-drive-link>`).
3. Open the notebooks from `notebooks/` in Colab with a **CPU runtime**; no GPU is needed.
4. Notebook `03` saves `sentinel_model.joblib` to Drive. Copy it into `models/` on the VM.

**Split by run, never by shuffled rows:** normal runs 1 to 4 train, 5 validation, 6 test;
attack runs 1 to 3 train, 4 validation, 5 to 6 test.

**Version pin:** a joblib model only loads reliably in the same scikit-learn version that saved
it. Check `sklearn.__version__` in Colab and put exactly that version in `requirements.txt`. The
detector refuses to start if the versions differ.

**Public benchmark (appendix only):** AdDDoSDN, MIT licence, Mendeley Data
`10.17632/9jp6r68y98.1`. It is not used to train the deployed model.

---

## How we work with Git

```bash
git checkout -b ilias/attacks          # one branch per person and topic
# ... work ...
git add -A && git commit -m "Add slow flood scenario"
git push -u origin ilias/attacks
```

Then open a **pull request** to `main` on GitHub. One other person reviews it before merging.

- Pull often: `git checkout main && git pull`, then `git rebase main` on your branch.
- Keep commits small and messages clear.
- Each person edits mainly their own folders (see the table at the top) to avoid conflicts.

---

## Troubleshooting

| Problem | Cause | Fix |
| --- | --- | --- |
| `OFPMMFC_INVALID_METER` | Switches on the kernel datapath | Use `datapath="user"` in `topo/lab_topo.py`, then `sudo mn -c` and **relaunch** Mininet |
| A rule added with `ovs-ofctl` disappears | ONOS deletes flows it did not install (flow reconciliation) | Install rules through the ONOS REST API with `appId=org.onosproject.rest` |
| Switches never appear in ONOS | ONOS still starting, or wrong controller address | Wait for `docker logs onos` to settle; the topology must use `127.0.0.1:6653` |
| `pingall` fails right after start | `fwd` app not active | `ssh -p 8101 onos@localhost`, then `app activate org.onosproject.fwd` |
| Spiger packets never reach the switch | Scapy sends on `lo` by default | Set `iface="h1-eth0"` in `sendp()` and run it inside `xterm h1` |
| Cannot paste in `xterm` | Ctrl+V does not work there | Use Shift+Insert or middle click |
| `permission denied` on Docker | Not in the `docker` group yet | Log out and back in, or `newgrp docker` |
| Old Mininet state | A previous run crashed | `sudo mn -c` |
| Detector refuses to start | scikit-learn version differs from Colab | Install the version stored in the model file |

---

## What never goes in this repo

- `.env`, passwords and the Grafana token
- `data/`, `models/`, `logs/` (shared through Google Drive instead)
- VM images or anything over a few MB
- Custom ONOS images with user accounts baked in (everyone uses the clean `onosproject/onos:2.7.0`)

All attacks in this project run **only inside the Mininet lab** on our own VMs.
