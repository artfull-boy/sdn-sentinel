# Sentinel ML part: how to check, rerun and recreate it

For teammates (and examiners) who want to verify the ML detector themselves, including on a
VM with little RAM. Status: 17 November 2026.

## What the ML part consists of

| File | Where | In Git? | What it is |
| --- | --- | --- | --- |
| `sentinel/features.py` | repo | yes | The one feature code, used for training and live (standard library only) |
| `sentinel/detector.py` | repo | yes | The live detector: polls ONOS every 2 s, scores ports, alerts the engine; also replays recordings |
| `sentinel/__init__.py` | repo | yes | Empty; makes `sentinel` a Python package |
| `notebooks/train_sentinel.ipynb` | repo | yes | Training, evaluation and all data checks, with outputs |
| `notebooks/add_new_runs.ipynb` | repo | yes | Checks new recordings and adds them to the training table or the extra test set; also records the history of the data |
| `data/labels.jsonl` | repo | yes | One line per recorded run (must include the S2_run2 line) |
| `data/sample/*.jsonl` | repo | yes | 3 small recordings (normal, slow flood, spoofing) for the replay check, phantom hosts removed |
| `data/features.csv` | shared Drive / GitHub Release | no | The training table: 34 runs, 43,038 rows (about 6 MB) |
| `data/features_busy.csv` | shared Drive / GitHub Release | no | Extra test set: 4 attack runs during busy traffic (never trained on) |
| `models/sentinel_model.joblib` | shared Drive / GitHub Release | no | The trained model (about 4.5 MB) |
| Raw recordings (zips: 644 MB from 9 Nov, plus the 17 Nov runs) | shared Drive / GitHub Release | no | Only needed to rebuild the feature tables |

Version pin: **scikit-learn 1.6.1** (the version that saved the model). The detector refuses to
start with another version. Colab used numpy 2.4.6 and pandas 2.2.3.

## Choose what you want to do

| Goal | Needs | RAM | Time | Section |
| --- | --- | --- | --- | --- |
| A. See the detector work | repo + model file | under 0.5 GB, no ONOS | 2 min | A |
| B. Retrain and check the numbers | `features.csv` + notebook | Google Colab (free) | 5 min | B |
| C. Rebuild the features from raw data | raw zip + `features.py` | Colab recommended | 25 min | C |
| D. Run it live | VM with ONOS | about 3-4 GB free | 30 min | D |
| E. Record new data (e.g. S2 with iperf) | VM with ONOS | about 3-4 GB free | 20 min per run | E |

## A. Replay check (no ONOS, no VM needed)

```bash
git clone https://github.com/artfull-boy/sdn-sentinel.git && cd sdn-sentinel
python3 -m venv .venv && . .venv/bin/activate
pip install scikit-learn==1.6.1 joblib numpy
# put sentinel_model.joblib into models/
python -m sentinel.detector --replay data/sample/S1_run2_first5min.jsonl --no-engine | tail -3
python -m sentinel.detector --replay data/sample/S5_run6.jsonl --no-engine | tail -3
python -m sentinel.detector --replay data/sample/S7_run6.jsonl --no-engine | tail -3
```

Expected with the current model (the exact alert counts are in section 11 of the pushed notebook):

| Recording | Expected summary |
| --- | --- |
| S1_run2_first5min (normal) | `no alerts` |
| S5_run6 (slow flood) | alerts on `s1:1` only, type `slow_exhaustion` |
| S7_run6 (spoofing) | alerts on `s1:1` only, type `spoofing` (possibly `unknown` first) |

## B. Retrain in Colab (no VM needed)

1. Copy `features.csv`, `features_busy.csv`, the `sentinel/` folder and `data/sample/` into
   **your own** `MyDrive/sdn-sentinel/` (files shared with you sit under "Shared with me", which
   Colab cannot reach by that path).
2. Open `notebooks/train_sentinel.ipynb` in Colab, Runtime → Change runtime type → **CPU**.
3. Runtime → Run all. Approve the Drive access.
4. It saves a new model to `MyDrive/sdn-sentinel/sentinel_model.joblib`, so it never touches
   anyone else's copy.

Expected numbers (same data, same code and seed give the same model). Values marked * come from
the hold experiment run on 17 Nov; the pushed notebook's own outputs are the reference.

| Output | Value |
| --- | --- |
| Section 2 | `(43038, 20)`, 34 runs, 6 edge ports |
| Section 4 | trained on 16370 normal windows |
| Section 4.1 | tau = 0.7040 (percentile 100.0 of validation normal) |
| Section 7 | 3 classes, trained on 436 attack windows |
| Section 8.1, ML both paths (10 s hold) | precision 0.922*, recall 0.754*, false alerts/hour 2.0 |
| Section 8.1, recall per type | flood 0.879*, slow_exhaustion 0.944*, spoofing 0.31 |
| Section 8.2 | ML 8 of 8 attack runs, threshold approximation 4 of 8 |
| Section 8.5 | 4 of 4 busy-traffic attack runs detected, 0 false-alarm windows |
| Section 9.1 | score difference 0.0, 100% same predictions |
| Section 9.3 | hold 0 / 3 / 5 / 10 windows table; 5 is used |

If any of these differ, check the scikit-learn version first (section 1 prints it).

## C. Rebuild `features.csv` from the raw recordings

Use Colab: unzipping needs 5.4 GB of disk, which a small VM may not have. `features.py` reads each
recording line by line and keeps only the last 6 snapshots in memory, so it needs little RAM.

```python
from google.colab import drive; drive.mount('/content/drive')
!unzip -q "/content/drive/MyDrive/sdn-sentinel/<dataset>.zip" -d /content/data
!python /content/drive/MyDrive/sdn-sentinel/sentinel/features.py /content/data \
    --labels /content/data/labels.jsonl --out /content/features.csv
```

It prints one `ok` line per recording (about 20 minutes in total). If `labels.jsonl` lacks the
S2_run2 line, that run is skipped: add the line first (it is in `labels_s2.jsonl` on the Drive).

## D. Run it live on the VM

Order matters:

```bash
docker restart onos                      # clears phantom hosts left by earlier floods; wait 1-2 min
sudo mn -c
sudo python3 topo/lab_topo.py --link-s3
mininet> pingall                         # FIRST, so every host is learned at its real port
# in another terminal, from the repo with the venv active:
python -m sentinel.detector --no-engine --log logs/alerts.jsonl     # detection only
python -m sentinel.detector --log logs/alerts.jsonl                 # with Abdo's engine on :9202
```

Then run an attack from h1 (`sudo python3 scenarios/run_scenario.py S5`, then S6, then S7).
Expected: alerts on `s1:1` within about 10 s of the attack starting, none on other ports.

### Low-RAM tips

| Uses RAM | About | Tip |
| --- | --- | --- |
| ONOS (Java, Docker) | 2 GB | The big one; nothing to cut |
| Grafana + Prometheus | 0.3-0.5 GB | For a detection-only test: `docker stop grafana prometheus` |
| Detector | 0.2-0.3 GB | Fine |
| Mininet + OVS | small | Fine |
| Browser tabs on the VM | varies | Close the ONOS GUI tab when not needed |

* Do not run `raw_recorder.py`, `bridge_exporter.py` and `detector.py` all at once on a small VM:
  each polls ONOS, and during a flood those polls are heavy.
* Check with `free -h` and `docker stats` before starting an attack.
* Do not unzip the raw dataset on the VM; use Colab for anything that needs it.

### Detector metrics for the dashboard (port 9201)

| Metric | Meaning |
| --- | --- |
| `sentinel_window_new_flows{switch,port}` | New flows on the port in the last 10 s |
| `sentinel_anomaly_score{switch,port}` | Isolation Forest score (higher = more unusual) |
| `sentinel_tau` | The alarm line for that score (draw it on the score panel) |
| `sentinel_attack_type{switch,port}` | 0 none, 1 flood, 2 slow_exhaustion, 3 spoofing, 4 unknown |

The detector's new-flow metric is deliberately **not** called `sentinel_new_flows`: that name belongs
to `monitoring/bridge_exporter.py` (per-second rate per switch), and `monitoring/rules.yml` adds up
every series of that name for the threshold panel.

### How the detector decides (summary)

* **Volume path:** anomaly score above tau for 2 windows in a row; the alert is then held for 10 s
  (`volume_hold` in the model file; set `VOLUME_HOLD = 0` in the notebook to switch it off).
* **Identity path:** a host appearing away from its home port; held for 10 s.
* **Type:** Random Forest, `unknown` below 70% confidence.
* Alerts go to `POST :9202/mitigate` when a port is first flagged, when its type changes, and every
  10 s while it stays flagged.

## E. Recording new data (for example S2 with working iperf)

The S2 recordings turned out to contain no iperf traffic (host ports received 14-26 packets in
15 minutes). `scenarios/traffic_gen.py` hides all command output, so a missing `iperf` binary fails
silently. Before recording:

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

Repeat with `S2_run4`. Check afterwards that the host ports' `rx` counters grew by hundreds of
thousands or more. Then share the files and the new `labels.jsonl` lines.

**Adding them:** `notebooks/add_new_runs.ipynb` checks the recordings, builds their features and
either adds them to the training table (`TARGET = 'train'`) or to the extra test set
(`TARGET = 'extra_test'`), keeping a backup of the previous table. Then rerun
`train_sentinel.ipynb`. Restart ONOS (`docker restart onos`) before **each** recording, or phantom
hosts pile up from run to run.

Always record with `--interval 2`: the model is trained on 2-second snapshots.
