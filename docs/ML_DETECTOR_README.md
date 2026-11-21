# Sentinel ML detector

This part of SDN Sentinel watches every edge port of the network and decides, every 2 seconds,
whether a port is attacking the controller. If it is, the detector names the attack type and
tells the mitigation engine (Abdo's part), which then limits or blocks the port.

This README is the one guide for the ML part. It covers what the model is, how it detects
attacks, how to run it **live against attacks you launch yourself**, how it works with the
engine, and (sections 10-12) how to retrain it, rebuild the dataset and record new data.

---

## 1. Before you run anything

The trained model is **not in Git** (it is a binary file). Get it first:

1. Download `sentinel_model.joblib`: **https://drive.google.com/file/d/1R0Z6Rh5cLmLSq-RMOinEiqtHsrkIh6_l/view?usp=sharing** (view-only).
2. From the repo root:
   ```bash
   mkdir -p models
   mv ~/Downloads/sentinel_model.joblib models/
   pip install -r requirements.txt        # needs scikit-learn 1.6.1 exactly
   ```
   scikit-learn must be **1.6.1**, the version that saved the model; the detector refuses to
   start with another version.
3. **Always run commands from the repo root** (the folder that contains `models/`), for
   example `python -m sentinel.detector`. From inside `sentinel/` you get
   `FileNotFoundError: models/sentinel_model.joblib`.

The engine reads the same file (it takes the alarm line `tau` from it), so it must be in
`models/` on every machine that runs the detector or the engine.

---

## 2. Where it fits

```
 Mininet hosts ──> OVS switches ──PACKET_IN──> ONOS (reactive forwarding)
                                                  │  REST, every 2 s
                                                  ▼
                                   sentinel/detector.py  (this part)
                                   features -> model -> decision
                                     │                    │
                     POST :9202/mitigate          metrics on :9201
                                     ▼                    ▼
                         sentinel/engine.py         Prometheus -> Grafana
                         (Abdo: meter / drop,      (Kluivert: dashboard)
                          rollback, guardrails)
```

The detector only **reads** ONOS. It never installs rules itself; the engine does that.

---

## 3. How it detects attacks

### 3.1 What it looks at

Every 2 s the detector takes a snapshot from ONOS (flows, port counters, hosts). For each edge
port it looks at the **last 10 seconds** (6 snapshots) and computes 11 numbers:

| Feature | Meaning in plain words |
| --- | --- |
| `new_flows` | How many new flow rules appeared for this port in 10 s |
| `new_flows_max_step` | The biggest jump in any single 2 s step |
| `burstiness` | How uneven the new flows were (high for pulsed attacks) |
| `active_steps` | In how many of the 5 steps new flows appeared |
| `uniq_src_mac` / `uniq_dst_mac` | How many different source / destination MACs the flows used |
| `rx_pkts` | Packets received on the port |
| `flows_per_pkt` | New flows per packet (normal traffic reuses flows, a flood doesn't) |
| `host_moves_in` | A known host suddenly appearing on this port, away from its home port |
| `table_size_sw` / `table_growth` | Size of the switch's flow table, and how fast it grew |

Nothing here is specific to one attack. These are general signs of "this port is costing the
controller far more than normal".

### 3.2 The decision: two stages

**Stage 1: is this port behaving abnormally?** Two paths. Either one flags the port.

* **Volume path (Isolation Forest).** The model was trained **only on normal traffic** (idle,
  pings, iperf, mixed). It gives every window an *anomaly score*. If the score goes above the
  alarm line `tau` for **2 windows in a row**, the port is flagged. The flag is then held for
  10 s, so a pulsed flood doesn't switch the alert on and off. The hold can only keep an alert
  going; it can never start one. Because it learned "normal" rather than specific attacks, it
  can also flag attack patterns it has never seen.
* **Identity path (spoofing).** A host that suddenly shows up on a different port from its
  home port is flagged right away (held for 10 s). This is the one hand-written rule, because a
  spoofing attack sends very little traffic and so doesn't look unusual by volume.

**Stage 2: what kind of attack?** For flagged ports only, a **Random Forest** (trained on
labelled attacks) names the type: `flood`, `slow_exhaustion` or `spoofing`. If it is less than
70% sure, the type is `unknown`. The port is still reported, so a new kind of attack isn't
ignored.

### 3.3 What it was trained on and how well it did

* Data: 34 recorded runs (43,038 port-windows) from our own testbed. The attacker was always
  h1 (port `s1:1`). Normal traffic came from all 6 host ports.
* Results on runs the model never saw (full details in the notebook):

| | ML detector | Threshold rule (our Lab 2 implementation, per-port approximation) |
| --- | --- | --- |
| Attack runs detected | **8 of 8**, first alert 0-6 s after the start | 4 of 8, misses every slow flood |
| Precision / recall (per window) | 0.92 / 0.75 | n/a |
| False alerts | 2 per hour of normal traffic | n/a |
| Attacks during heavy iperf traffic (never trained on) | 4 of 4, first alert after 4-12 s, no innocent port flagged | n/a |
| Type correct (flagged attack windows) | 94% | n/a (gives no type) |

Known weak spots: spoofing is caught early in each run but only about 31% of its windows are
flagged (the identity path fires when the host moves, not on every window); some flood windows
are labelled `spoofing` by the classifier.

---

## 4. Running it live

### 4.1 Start order (it matters)

```bash
# terminal 1: clean start
docker restart onos            # clears "phantom hosts" left by earlier floods; wait 1-2 min
sudo mn -c
sudo python3 topo/lab_topo.py --link-s3
mininet> pingall               # FIRST: every host must be learned at its real port

# terminal 2: from the repo root
python -m sentinel.detector --no-engine --log logs/alerts.jsonl        # detection only
#   or, with Abdo's engine running on :9202:
python -m sentinel.detector --log logs/alerts.jsonl
```

Why `pingall` before the detector: the detector remembers each host's **home port** the first
time it sees it. If it starts while a spoofing attack is already running, it learns the wrong
home and misses the attack.

At start it prints the model settings, then `live: polling ... every 2.0 s`. With no attack it
stays quiet. That silence is the expected result for normal traffic.

### 4.2 Low-RAM tips

| Uses RAM | About | Tip |
| --- | --- | --- |
| ONOS (Java, Docker) | 2 GB | The big one; nothing to cut |
| Grafana + Prometheus | 0.3-0.5 GB | For a detection-only test: `docker stop grafana prometheus` |
| Detector | 0.2-0.3 GB | Fine |
| Mininet + OVS | small | Fine |

Don't run `raw_recorder.py`, `bridge_exporter.py` and the detector all at once on a small VM:
each polls ONOS, and during a flood those polls are heavy. Check `free -h` and `docker stats`
before starting an attack.

### 4.3 What an alert looks like

Example (illustrative values):

```
1794225031.2  s1:1   ALERT new          flood           score=0.812 conf=0.93 via volume
1794225041.3  s1:1   ALERT still active flood           score=0.790 conf=0.95 via volume
1794225061.4  s1:1   cleared
```

* `new` = first alert on this port; `type change` = the classifier changed its mind;
  `still active` = repeated every 10 s while the attack goes on (the engine uses this to know the
  attack hasn't stopped); `cleared` = the port is back to normal (logged only, not sent).
* `via volume` / `via identity` / `via volume+identity` = which path flagged it.
* With the engine on, the engine's reply is shown after `->`.
* Every line is also saved as JSON in `logs/alerts.jsonl`, to compare with attack start times
  afterwards.

### 4.4 Attacks to test with

**A. The scripted scenarios** (the same attacks as the training data, but new runs):

```bash
sudo python3 scenarios/run_scenario.py S4    # constant flood, 80 pkt/s
sudo python3 scenarios/run_scenario.py S5    # slow flood, 8 pkt/s
sudo python3 scenarios/run_scenario.py S6    # pulsed flood, 80 pkt/s, 2 s on / 6 s off
sudo python3 scenarios/run_scenario.py S7    # spoofing h6 from h1
```

Each runs 60 s normal, 60 s attack, 60 s recovery. These scenarios always attack from h1, so
**expected:** alerts on `s1:1` (h1's port) only, starting
within about 10 s of "phase 2: attack", with the matching type, then `cleared` about 10 s after the
attack ends. Restart ONOS (and `pingall` again) between attacks.
Note: `run_scenario.py` appends a line to `data/labels.jsonl` each time. Don't commit those
lines unless the run is also recorded and meant for the dataset.

**B. Variations the model has never seen.** These are the real test of "detect without being
tuned for each attack". In training, every attack came from h1 (`s1:1`) at 8/s or 80/s.

From h1, at the Mininet prompt:

```bash
mininet> h1 python3 scenarios/attacks/flood.py --rate 20 --duration 60 &
mininet> h1 python3 scenarios/attacks/flood.py --rate 40 --duration 60 &
mininet> h1 python3 scenarios/attacks/flood.py --rate 150 --duration 60 &
mininet> h1 python3 scenarios/attacks/spoof.py --rate 0.5 --duration 60 &
```

From another host (needs the updated attack scripts, which detect the host's own interface), from a
normal terminal in the repo:

```bash
H3=$(pgrep -f "mininet:h3$" | head -1)
sudo mnexec -a $H3 python3 scenarios/attacks/flood.py --rate 80 --duration 60
sudo mnexec -a $H3 python3 scenarios/attacks/spoof.py --rate 2 --duration 30
```

Replace `h3` with any host (`h5` attacks from `s3:1`). Write down the start time of each attack so
you can compare it with `logs/alerts.jsonl`, and restart ONOS and `pingall` between attacks.

**Measured live on 20 Nov** (Ilias):

| Attack | Attacker port | New for the model | Result |
| --- | --- | --- | --- |
| Flood 20/s (below the threshold rule's 30/s) | `s1:1` | rate | Flagged for the whole attack; type `slow_exhaustion` / `unknown` |
| Flood 40/s | `s1:1` | rate | Flagged for the whole attack; type `flood` / `unknown` |
| Flood 150/s | `s1:1` | rate | Flagged, `flood` (0.99) |
| Spoofing 0.5/s | `s1:1` | rate | Flagged via identity, `unknown` then `spoofing` |
| Flood 80/s from h3 | `s1:2` | port | Flagged, `flood` (0.98-0.99) |
| Flood 80/s from h5 | `s3:1` (other switch) | port | Flagged, `flood` (0.99) |
| Spoofing 2/s from h3 | `s1:2` | port | Flagged via identity, `spoofing` (0.86-0.88) |

In every case only the attacker's port was flagged, including h1 during the h3 flood (same switch)
and the victim h6 during the h5 flood (same switch).

At rates between the trained ones (20, 40) the type switches between two labels and `unknown`.
That is expected: the attack is clearly abnormal but sits between the two flood types the classifier
knows. An `unknown` type is a correct result: the port is still flagged and the engine still acts.
Not yet tested: floods slower than 8/s, and pulsed floods with gaps longer than 10 s (these may show
`cleared` then `new` between bursts).

### 4.5 Checking without a VM (replay)

To check the code and model without ONOS, replay a recording:

```bash
python -m sentinel.detector --replay data/sample/S5_run6.jsonl --no-engine
```

Expected: `S1_run2_first5min.jsonl` (normal) gives `no alerts`; `S5_run6.jsonl` (slow flood)
gives alerts on `s1:1` only, type `slow_exhaustion`; `S7_run6.jsonl` (spoofing) gives alerts on
`s1:1` only, type `spoofing` (possibly `unknown` first). No ONOS or VM is needed, under 0.5 GB RAM.

The samples in `data/sample/` come from the same kind of runs as the training data, so they only
show that everything works, not how well it detects. The live tests above show that.

---

## 5. Working with the engine (Abdo's part)

**What the detector sends:** `POST http://localhost:9202/mitigate` with

```json
{"switch": "of:0000000000000001", "port": "1", "type": "flood",
 "score": 0.8123, "confidence": 0.93, "ts": 1794225031.2}
```

It is sent when a port is first flagged, when its type changes, and every 10 s while it stays
flagged. The detector does **not** send "cleared". The engine decides when to release, using its
own quiet timer.

**What the engine does with it** (from `sentinel/playbooks.yaml`; Abdo owns the details):

| Type | Action | Released after |
| --- | --- | --- |
| `flood` | Meter the port to 2 pkt/s; drop it if still attacking after 15 s | 30 s with no alert |
| `slow_exhaustion` | Meter to 2 pkt/s | 60 s with no alert |
| `spoofing` | Drop the spoofed MAC on the attacker's port | 60 s |
| `unknown` | Meter to 2 pkt/s and flag for a human | Manual |

**Testing them together:**
1. Start the engine in DRY_RUN mode first (it logs what it *would* do and installs nothing).
2. Start the detector **without** `--no-engine`. Each alert line should end with the engine's reply.
3. Run an attack from section 4.4. Check that the engine's log shows the expected action for the
   type, on `s1:1` only.
4. Then switch DRY_RUN off and repeat. In ONOS (`/onos/v1/flows`, appId `org.onosproject.rest`)
   you should see the meter or drop rule appear, the new-flow count on `s1:1` fall, and the rule
   removed after the release time.

If the engine is not running, the detector keeps working and prints `engine not reached`.

**What the live tests (19-20 Nov) showed, for the engine to handle:**

| Seen live | What the engine receives | Why it matters |
| --- | --- | --- |
| At the end of **every** flood, the type switches to `unknown` (confidence about 0.50) a few seconds before the alert clears | `flood`, `flood`, ..., then one `unknown` | If the `unknown` playbook acts on it, the port gets metered with no automatic release, after the attack is already over. Suggestion: ignore `unknown` for a port that is already being handled for another type |
| Spoofing alerts come and go every 20-30 s while the attack runs (the alert fires each time the host is moved back onto the attacker's port) | `spoofing` (new), `still active`, a gap, `spoofing` (new) again | Repeated "new" alerts for the same port and type should extend the existing action, not be refused or start a second one. With the drop rule in place the spoofed ARPs should stop, so this should mostly go away |
| Attacks came from `s1:1`, `s1:2` and `s3:1` (section 4.4) | Any edge port | The engine must not assume the attacker is h1 |
| Alerts continue about 20-25 s after an attack stops (the 10 s window empties, then the 10 s hold) | `still active` for about 20 s after the end | Release timers count from the last alert, so release happens about 20 s later than the attack end |

Start command (Abdo to fill in): `<engine start command, DRY_RUN and normal>`

---

## 6. Dashboard metrics (port 9201)

| Metric | Meaning |
| --- | --- |
| `sentinel_window_new_flows{switch,port}` | New flows on the port in the last 10 s |
| `sentinel_anomaly_score{switch,port}` | Isolation Forest score (higher = more unusual) |
| `sentinel_tau` | The alarm line; draw it on the score panel |
| `sentinel_attack_type{switch,port}` | 0 none, 1 flood, 2 slow_exhaustion, 3 spoofing, 4 unknown |

The detector's new-flow metric is deliberately **not** called `sentinel_new_flows`: that name
belongs to `monitoring/bridge_exporter.py` (per-second rate per switch), and `monitoring/rules.yml`
adds up every series of that name for the threshold panel.

**For the dashboard (Kluivert):** there is no separate collector for the ML part. The detector
itself publishes these metrics while it runs live (not in replay mode).

* Prometheus already scrapes it: job `detector`, target `localhost:9201` in
  `monitoring/prometheus.yml` (works because Prometheus runs with `network_mode: host`).
* Check it is up: `curl -s localhost:9201/metrics | grep sentinel_`. It should list one line per
  edge port.
* Labels: `switch="of:0000000000000001"`, `port="1"`. Values update every 2 s.
* `monitoring/bridge_exporter.py` (job `collector`, :9200) still feeds the threshold panel. The
  two run side by side.

Example queries:

| Panel | PromQL |
| --- | --- |
| Anomaly score per port, with the alarm line | `sentinel_anomaly_score` and `sentinel_tau` |
| Ports currently flagged | `sentinel_attack_type > 0` |
| Attack type on the attacker port | `sentinel_attack_type{switch="of:0000000000000001", port="1"}` (value mapping 0-4 as above) |
| New flows per port (10 s window) | `sentinel_window_new_flows` |

A good demo panel: `sentinel_anomaly_score` for `s1:1` with `sentinel_tau` as a line. During a
pulsed flood (S6) the old threshold panel stays quiet while the score crosses the line.

---

## 7. Detector options

| Option | Default | Use |
| --- | --- | --- |
| `--no-engine` | off | Detect and log only; send nothing to the engine |
| `--log FILE` | none | Save every alert as JSON |
| `--engine URL` | `http://localhost:9202` | Where the engine listens |
| `--model PATH` | `models/sentinel_model.joblib` | Use another model file |
| `--interval S` | 2.0 | Poll interval. Keep it at 2: the model was trained on 2 s snapshots |
| `--metrics-port N` | 9201 (live) | 0 turns the metrics off |
| `--replay FILE` | none | Score a recording instead of live ONOS |
| `--force` | off | Skip the scikit-learn version check (not for the demo) |

ONOS address and login come from `ONOS_URL`, `ONOS_USER`, `ONOS_PASS`
(defaults: `http://localhost:8181/onos/v1`, `onos`, `rocks`).

---

## 8. Troubleshooting

| Problem | Fix |
| --- | --- |
| `FileNotFoundError: models/sentinel_model.joblib` | Section 1: download the model, run from the repo root |
| scikit-learn version error | `pip install scikit-learn==1.6.1` |
| `cannot reach ONOS` | `docker ps`; wait 1-2 min after `docker restart onos` |
| `warning: poll+score took ... s` | VM is overloaded: stop Grafana/Prometheus or `raw_recorder.py` during the test |
| Alerts on a port that isn't attacking | Restart ONOS and `pingall` before starting the detector (old phantom hosts) |
| No alert during spoofing | The detector was started after the attack began, or `pingall` wasn't run first |
| `engine not reached` | Engine not running on :9202, or use `--no-engine` |

---

## 9. Files

| File | In Git? | What it is |
| --- | --- | --- |
| `sentinel/detector.py` | yes | The live detector (and replay mode) |
| `sentinel/features.py` | yes | Feature code, shared by training and live use (standard library only) |
| `sentinel/__init__.py` | yes | Empty; makes `sentinel` a Python package |
| `notebooks/train_sentinel.ipynb` | yes | Training, evaluation and all data checks, with outputs |
| `notebooks/add_new_runs.ipynb` | yes | Checks new recordings and adds them to the dataset; keeps the data history |
| `data/labels.jsonl` | yes | One line per recorded run (attack type, attacker port, start and end time) |
| `data/sample/*.jsonl` | yes | 3 small recordings for the replay check |
| `models/sentinel_model.joblib` | no, Drive | The model (about 4.5 MB; section 1) |
| `data/features.csv` | no, Drive | The training table: 34 runs, 43,038 rows (about 6 MB) |
| `data/features_busy.csv` | no, Drive | Extra test set: 4 attack runs during heavy traffic, never trained on |
| Raw recordings | no, Drive | 644 MB zip from 9 Nov plus the 17 Nov runs; only to rebuild the tables |

---

## 10. Retraining and checking the numbers (Colab, no VM)

1. Copy `features.csv`, `features_busy.csv`, the `sentinel/` folder and `data/sample/` into
   **your own** `MyDrive/sdn-sentinel/` (files shared with you sit under "Shared with me", which
   Colab can't reach by that path).
2. Open `notebooks/train_sentinel.ipynb` in Colab, Runtime → Change runtime type → **CPU**.
3. Runtime → Run all, and approve the Drive access.
4. It saves a new model to `MyDrive/sdn-sentinel/sentinel_model.joblib`, so it never touches
   anyone else's copy.

Same data, code and seed give the same model. Expected outputs (the pushed notebook's own outputs
are the reference):

| Notebook section | Value |
| --- | --- |
| 2 | `(43038, 20)`, 34 runs, 6 edge ports |
| 4 | trained on 16370 normal windows |
| 4.1 | tau = 0.7040 |
| 7 | 3 classes, trained on 436 attack windows |
| 8.1 (10 s hold) | precision 0.922, recall 0.754, 2.0 false alerts per hour |
| 8.1, recall per type | flood 0.879, slow_exhaustion 0.944, spoofing 0.31 |
| 8.2 | ML 8 of 8 attack runs, threshold approximation 4 of 8 |
| 8.5 | 4 of 4 busy-traffic attack runs detected; no innocent port flagged (10 windows flagged on `s1:1` just after the attack, from the 10 s hold) |
| 9.1 | score difference 0.0, 100% same predictions (no scaling needed for tree models) |
| 9.3 | hold 0 / 3 / 5 / 10 windows table; 5 (10 s) is used |

If anything differs, check the scikit-learn version first (section 1 of the notebook prints it).

---

## 11. Rebuilding `features.csv` from the raw recordings

Use Colab: unzipping needs 5.4 GB of disk, which a small VM may not have. `features.py` reads
each recording line by line, so it needs little RAM.

```python
from google.colab import drive; drive.mount('/content/drive')
!unzip -q "/content/drive/MyDrive/sdn-sentinel/<dataset>.zip" -d /content/data
!python /content/drive/MyDrive/sdn-sentinel/sentinel/features.py /content/data \
    --labels /content/data/labels.jsonl --out /content/features.csv
```

It prints one `ok` line per recording (about 20 minutes in total). A recording with no line in
`labels.jsonl` is skipped.

---

## 12. Recording new data

`scenarios/traffic_gen.py` hides command output, so a missing `iperf` fails silently (this is
why the first S2 recordings had no iperf traffic). Check before recording:

```bash
which iperf || sudo apt install -y iperf
docker restart onos && sudo mn -c && sudo python3 topo/lab_topo.py --link-s3
mininet> pingall
mininet> iperf h2 h6            # must report Mbits/sec or Gbits/sec
```

Then, in two other terminals:

```bash
python3 scenarios/raw_recorder.py data/raw/S2_run3.jsonl --interval 2 --duration 960
sudo python3 scenarios/run_scenario.py S2 --duration 900
```

* Always record with `--interval 2`: the model is trained on 2-second snapshots.
* Restart ONOS before **each** recording, or phantom hosts pile up from run to run.
* Afterwards, check that the host ports' `rx` counters grew as expected, then share the file and
  its new `labels.jsonl` line.

**Adding them:** `notebooks/add_new_runs.ipynb` checks the recordings, builds their features and
adds them either to the training table (`TARGET = 'train'`) or to the extra test set
(`TARGET = 'extra_test'`), keeping a backup of the old table. Then rerun `train_sentinel.ipynb`
(section 10).
