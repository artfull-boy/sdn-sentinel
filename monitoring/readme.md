# Sentinel: dashboard and evaluation

This README covers **Nkwenti's part** of the Sentinel group project: Prometheus,
Grafana, the Lab 2 rule baseline, evaluation scripts, and the results/report
deliverables. It is not a setup guide for the full ONOS/Mininet/ML project.

## What this part delivers

- Prometheus scrapes the collector, detector, and mitigation engine.
- Grafana displays Sentinel's metrics, baseline rule, detections, and mitigation
  actions in one dashboard.
- A Prometheus recording rule tracks whether the Lab 2 threshold baseline would
  fire. It is for comparison and **does not install mitigations**.
- `eval/evaluate.py` produces reproducible CSV tables from saved run labels and
  service logs.
- Saved run results, dashboard screenshots, report figures, and the evaluation
  section document how the ML detector compares with the baseline.

## Prerequisites and start-up

Run these commands from the repository root. Docker Compose starts the shared
services, so ONOS and the Sentinel services must be available for their
Prometheus targets to report `UP`.

```bash
docker compose up -d
docker compose ps
```

Open:

- Prometheus: <http://localhost:9090/targets>
- Grafana: <http://localhost:3000>

The Grafana login is `admin`; the password is `GF_SECURITY_ADMIN_PASSWORD` in
your local `.env` file. Do not commit `.env` or passwords. The provisioned
dashboard is named **Sentinel**.

## Prometheus and the baseline rule

Configuration is in `monitoring/prometheus.yml`; the baseline is in
`monitoring/rules.yml`. Prometheus scrapes the collector, detector, and engine
every **1 second** and evaluates the rule every **1 second**. 

The recording rule `sentinel:rule_baseline:fired` is `1` when the sum of
`sentinel_new_flows` is over 30 for three consecutive one-second evaluations;
otherwise it is `0`. It records the traditional threshold baseline for
comparison only. It does not alert the mitigation engine or take action.

After changing Prometheus configuration, restart or reload Prometheus and check
<http://localhost:9090/targets>. Collector, detector, and engine should show
`UP` when those services are running. Confirm the baseline series in the
Prometheus query page with:

```promql
sentinel:rule_baseline:fired
```

## Grafana dashboard and metric contract

Dashboard JSON and provisioning are under
`monitoring/grafana/provisioning/`. The dashboard includes the flow-table
reference, new flows and the 30/s threshold, rule state, anomaly score and
threshold, attack type, active mitigations, and ML-versus-rule/action timelines.
It refreshes every five seconds; that display refresh does not set the
collection or Prometheus scrape frequency.

The services must export the shared metrics for their panels to show data:

- Collector: `sentinel_new_flows` with `{switch, port}` labels.
- Detector: `sentinel_anomaly_score` and
  `sentinel_anomaly_threshold`; the latter is the current model threshold.
- Detector: `sentinel_attack_type` as a one-hot gauge with
  `{switch, port, type}` labels. Use `normal`, `flood`, `slow_exhaustion`, or
  `spoofing`; set the current type to `1` and other types to `0`.
- Engine: `sentinel_mitigation_active` and `sentinel_actions_total`.
  `sentinel_actions_total` needs an `action` label for dashboard grouping and
  annotations.

These are shared integration contracts. If a target is `UP` but a panel is
empty, check whether its service exports the metric and labels the panel
expects; a scrape target being `UP` does not mean every metric is present.

## Evaluate recorded runs

`eval/evaluate.py` analyzes existing data; it does not collect ONOS data, run
scenarios, or create missing labels or audit events. It needs the run labels
from `data/labels.jsonl` and the engine audit log from `logs/audit.jsonl`.
Optionally supply baseline samples and S10 ping probes:

```bash
python3 eval/evaluate.py \
  --labels data/labels.jsonl \
  --audit logs/audit.jsonl \
  --rule-samples results/rule_samples.csv \
  --ping-log results/s10_ping.csv \
  --output-dir results
```

The labels file has one JSON object per run, including `run_id`, `scenario`,
`label`, `t_start`, and `t_end`. The audit log is JSONL; each event needs a
timestamp (`ts` or `timestamp`) and should include `switch`, `port`, `type`,
`action`, and `onos_status`.

Optional CSV formats:

- Rule samples: either `ts,rule_fired` (recorded baseline state) or
  `ts,switch,new_flows` (per-switch rates, summed by timestamp). The evaluator
  applies the baseline's over-30-for-three-consecutive-seconds rule to flow
  samples.
- Ping probes: `run_id,ts,success,latency_ms`. Use `1`/`true` or `0`/`false`
  for `success`; failed probes may have an empty latency.

The script writes:

- `results/ml_vs_rule.csv` — ML and baseline outcomes for core scenarios S1–S7.
  Without `--rule-samples`, baseline results are marked unavailable, not
  missed.
- `results/timing.csv` — per-attack detection time, time from detection to a
  successful mitigation, and time from attack end to successful recovery.
- `results/timing_summary.csv` — median timing values by scenario.
- `results/collateral_damage.csv` — probe loss and successful-probe latency
  statistics, when `--ping-log` is supplied.

The results describe only the supplied logs. Missing samples or events are not
filled in or counted as successful detections.
 
