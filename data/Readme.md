# Sentinel dataset — handoff to Aishwarya

## The one paragraph that explains everything

This folder is **raw ONOS state, photographed once every 2 seconds**. It is not
features yet. Each photograph (a "sample") lists every flow rule, every port's
packet counters, and where every host sits, at that instant. Your job: read these
photographs, and for each network port compute how things *changed* over a 10
second window (= 5 samples), which gives the 12 numbers the model trains on. You
write that feature code once (`features.py`) and use it in two places: here to
build the training table, and live inside `detector.py`. Same code both times, so
the model sees identical numbers in training and in production.

---

## 1. What you received

```
data/
  raw/
    S1_run1.jsonl, S1_run2.jsonl     normal — pingall
    S2_run1.jsonl, S2_run2.jsonl     normal — iperf (bulk TCP)
    S3_run1.jsonl, S3_run2.jsonl     normal — mixed
    S4_run1..6.jsonl                 attack — flood, constant
    S5_run1..6.jsonl                 attack — slow flood (evades the Lab 2 rule)
    S6_run1..6.jsonl                 attack — pulsed flood (evades the rule)
    S7_run1..6.jsonl                 attack — identity spoofing
  labels.jsonl                       one line per run: when the attack ran, from which port
```

30 runs. Normal runs are 15 minutes; attack runs are 3 minutes (60s normal, then
60s attack, then 60s recovery). Each `.jsonl` file is one run.

---

## 2. What ONE sample contains (read this carefully)

A capture file is line-delimited JSON. **Line 1 is metadata. Every line after it
is one 2-second snapshot.** Here is a real snapshot, annotated:

```json
{
  "type": "sample",
  "ts": 1762531002.0,                         <- WHEN: epoch seconds. This is your join key.

  "flows": [                                  <- every flow rule in the network right now
    {
      "id": "1000abc...",                      <- unique id. Compare ids between two samples
                                                  to see which flows are NEW.
      "dev": "of:0000000000000001",            <- which switch (here s1)
      "inport": "1",                           <- which port the flow matches on (here s1 port 1 = h1)
      "ethsrc": "02:ab:cd:...",                <- source MAC the flow matches
      "ethdst": "00:00:00:00:00:06",           <- destination MAC (here h6)
      "pkts": 12                               <- packets that hit this flow so far
    }
    // ... one object per flow. Normal: ~70 flows. During a flood: thousands.
  ],

  "ports": [                                  <- packet counters per switch port
    {
      "dev": "of:0000000000000001",
      "port": "1",
      "rx": 340,                               <- packets RECEIVED on this port, CUMULATIVE
      "tx": 310                                <- packets SENT. Cumulative since boot, so you
    }                                             take the difference between two samples.
    // ... one per switch port
  ],

  "hosts": [                                  <- where ONOS thinks each host lives right now
    {
      "mac": "00:00:00:00:00:06",             <- h6
      "dev": "of:0000000000000003",            <- on switch s3 ...
      "port": "2"                              <- ... port 2. If this suddenly changes, a host moved.
    }
    // ... one per host
  ]
}
```

Three things to internalise:

- **`flows` is a full snapshot, not a delta.** To get "new flows this step" you
  diff this sample's flow `id`s against the previous sample's. An id present now
  but not before = a new flow.
- **`ports[].rx` is cumulative** (it only ever goes up). "Packets in this step" =
  `rx_now - rx_previous`.
- **A port is identified by `(dev, port)`**, e.g. `("of:0000000000000001", "1")`.
  You attribute a flow to a port via its `inport`.

### The meta line (line 1)

```json
{"type": "meta", "run_id": "S4_run1", "started": 1762531000.0,
 "links": [{"src": "of:0000000000000001/3", "dst": "of:0000000000000002/3"}, ...]}
```

`links` is the list of **switch-to-switch** ports. You need it to separate the 6
**edge ports** (where hosts connect: s1:1, s1:2, s2:1, s2:2, s3:1, s3:2) from the
core ports. Features are computed on edge ports only; a port that appears in
`links` is core, skip it.

---

## 3. How a sample is USED — one feature, worked out

Take two consecutive samples, 2 seconds apart, and look at edge port `s1:1`.

**Sample A (ts = 1762531002):** flows on `s1:1` have ids `{f1, f2, f3}`,
and `ports` says `s1:1` rx = 340.

**Sample B (ts = 1762531004):** flows on `s1:1` have ids `{f3, f4, f5, f6}`,
and `ports` says `s1:1` rx = 520.

From this one step you get:
- **new flows** = ids in B not in A = `{f4, f5, f6}` = **3**.
- **packets this step (rx_pkts)** = 520 − 340 = **180**.
- **flows_per_pkt** = 3 / 180 = **0.0167**.

Now slide that across a **10 second window = 5 samples**, and aggregate: sum the
new flows, take the std dev for burstiness, count the distinct source MACs, and so
on. That gives one feature row for `s1:1` for that window. Repeat for every edge
port and every window in the run. That is the training table.

> On a flood, `new flows` per step is huge and `flows_per_pkt` is near 1 (almost
> every packet makes a new flow). On normal iperf, `new flows` is ~0 and
> `flows_per_pkt` is near 0 (thousands of packets, no new flows). That gap is what
> the model learns.

---

## 4. The 12 features (all per edge port, per 10s window)

| # | Feature | How to compute it from the samples |
|---|---------|------------------------------------|
| 1 | `new_flows` | sum of per-step new flow ids on this port, across the window |
| 2 | `new_flows_max_step` | the largest single-step new-flow count in the window (see note) |
| 3 | `burstiness` | std dev of the per-step new-flow counts |
| 4 | `active_steps` | how many of the 5 steps had new_flows > 0 |
| 5 | `uniq_src_mac` | count of distinct `ethsrc` across flows on this port in the window |
| 6 | `uniq_dst_mac` | count of distinct `ethdst` across flows on this port |
| 7 | `rx_pkts` | `ports[].rx` at window end minus at window start, for this port |
| 8 | `flows_per_pkt` | `new_flows` / `rx_pkts` (if rx_pkts is 0, use 0) |
| 9 | `hosts_on_port` | number of `hosts[]` located on this port at window end |
| 10 | `host_moves_in` | how many hosts changed location TO this port during the window |
| 11 | `table_size_sw` | total flow count on this port's switch at window end (flows where `dev` = this switch) |
| 12 | `table_growth` | `table_size_sw` at window end minus at window start |

> **Note on #1 and #2.** They were specified for a 1-second step, but this capture
> is 2 seconds (the recorder slowed down so it could keep up with the flood). So a
> "step" here is 2s. `new_flows` still works. `new_flows_max_step` is a 2s max, not
> 1s. Keep whatever definition you pick identical in training and live.

---

## 5. How to label each feature row

`labels.jsonl`, one line per run:

```json
{"run_id": "S5_run1", "scenario": "S5", "label": "slow_exhaustion",
 "attacker": "of:0000000000000001:1", "t_start": 1762531500.0, "t_end": 1762531560.0}
```

Rule for labelling a feature row (one port, one window):

> It gets the run's `label` **only if** the run is an attack run **and** the port
> is the run's `attacker` port **and** the window overlaps `[t_start, t_end]`.
> Otherwise it is `normal`.

So in an `S5` run, only windows on `of:0000000000000001:1` during the 60s attack
are `slow_exhaustion`. The 60s normal lead-in, the 60s recovery, and every other
port, are all `normal`. Normal runs (`label: normal`, `attacker: null`) are normal
for the whole run.

The four class names: `normal`, `flood` (S4 and S6), `slow_exhaustion` (S5),
`spoofing` (S7).

---

## 6. Four rules that protect the results

1. **One `features.py`, used twice.** Build features from these files with it, and
   import the same file in `detector.py` for live scoring. If training features and
   live features are computed by different code, the model silently degrades.
2. **Live detector must poll every 2 seconds**, to match this capture's step.
3. **Split by run, not by shuffled rows.** Rows from one run are correlated. For
   each class: run1+run2 train, one run validation, one run test. Write the split
   down so results reproduce.
4. **Pin scikit-learn to your Colab version** in `requirements.txt`. Train in
   Colab, run `import sklearn; sklearn.__version__`, and set that exact version.
   The `.joblib` only loads on a matching version, or the VM detector crashes.

---

## 7. Your path from here

1. `features.py`: read a `.jsonl`, walk samples in time order, emit one row per
   edge port per 10s window (section 4). Reuse it live.
2. Join rows to labels by `ts` and attacker port (section 5).
3. Notebook 01: plot each feature per class, confirm normal vs S5/S6 separate.
4. Notebook 02: Isolation Forest on normal-only; threshold at the 99.5th percentile
   of validation-normal scores.
5. Notebook 03: Random Forest for attack type on the flagged windows.
6. Export `sentinel_model.joblib`.

Format questions → ask Ilias. The recorder is `scenarios/raw_recorder.py` if you
want to see exactly how each field is produced.
