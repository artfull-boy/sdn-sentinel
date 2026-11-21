#!/usr/bin/env python3
"""Build reproducible Sentinel evaluation tables from saved run and service logs."""

import argparse
import csv
import json
import math
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


CORE_SCENARIOS = {f"S{i}" for i in range(1, 8)}
NORMAL_LABELS = {"", "normal", "none", "benign"}
RELEASE_ACTIONS = ("release", "recover", "remove", "rollback")
FAILURE_WORDS = ("fail", "error", "reject", "timeout")
NO_ACTIONS = {"", "none", "observe", "dry_run", "dry-run", "no_action"}
TRUE_VALUES = {"1", "true", "success", "ok"}
FALSE_VALUES = {"0", "false", "failure", "failed", "no", "timeout"}


def timestamp(value):
    """Parse Unix seconds (or milliseconds) and ISO-8601 timestamps."""
    try:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError(f"invalid timestamp {value!r}")
        return result / 1000 if result > 100_000_000_000 else result
    except (TypeError, ValueError):
        pass

    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"ISO-8601 timestamp must include a timezone: {value!r}")
    return parsed.timestamp()


def read_jsonl(path):
    records = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            records.append(record)
    return records


def normalize(value):
    return str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")


def is_attack_type(value):
    return normalize(value) not in NORMAL_LABELS


def type_matches(observed, expected):
    observed, expected = normalize(observed), normalize(expected)
    if observed == expected:
        return True
    return observed == "flood" and expected in {"flood", "pulsed_flood"}


def read_labels(path):
    labels = read_jsonl(path)
    if not labels:
        raise ValueError(f"{path}: no labelled runs found")
    for index, row in enumerate(labels, 1):
        for key in ("run_id", "scenario", "label", "t_start", "t_end"):
            if key not in row:
                raise ValueError(f"{path}: record {index} is missing {key!r}")
        row["t_start"] = timestamp(row["t_start"])
        row["t_end"] = timestamp(row["t_end"])
        if row["t_end"] < row["t_start"]:
            raise ValueError(f"{path}: record {index} ends before it starts")
    return labels


def read_audit(path):
    events = read_jsonl(path)
    if not events:
        raise ValueError(f"{path}: no audit events found")
    for index, event in enumerate(events, 1):
        ts = event.get("ts", event.get("timestamp"))
        if ts is None:
            raise ValueError(f"{path}: audit record {index} is missing 'ts'")
        event["_ts"] = timestamp(ts)
    return sorted(events, key=lambda event: event["_ts"])


def attack_port_matches(event, label):
    attacker = label.get("attacker")
    if not attacker or not event.get("switch") or event.get("port") is None:
        return True
    switch, separator, port = str(attacker).rpartition(":")
    return not separator or (
        str(event["switch"]) == switch and str(event["port"]) == port
    )


def run_events(events, label):
    start, end = label["t_start"], label["t_end"]
    return [
        event for event in events
        if start <= event["_ts"] <= end and attack_port_matches(event, label)
    ]


def successful_action(event):
    action = normalize(event.get("action"))
    if action in NO_ACTIONS or any(word in action for word in FAILURE_WORDS):
        return False
    status = normalize(event.get("onos_status"))
    return status not in {"false", "0", "failed", "failure"} and not any(
        word in status for word in FAILURE_WORDS
    )


def is_release(event):
    action = normalize(event.get("action"))
    return any(word in action for word in RELEASE_ACTIONS + ("uninstall", "clear"))


def read_rule_samples(path):
    """Read either fired-state samples or network-wide new-flow samples."""
    grouped = defaultdict(lambda: {"new_flows": [], "fired": []})
    modes = set()
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError(f"{path}: CSV is missing a header")
        for line_number, row in enumerate(reader, 2):
            time_value = next(
                (row[key] for key in ("ts", "timestamp", "time") if row.get(key)),
                None,
            )
            if time_value is None:
                raise ValueError(f"{path}:{line_number}: missing ts/timestamp/time")
            ts = timestamp(time_value)
            fired_value = next(
                (row[key] for key in (
                    "rule_fired", "sentinel:rule_baseline:fired",
                ) if row.get(key) not in (None, "")),
                None,
            )
            if fired_value is not None:
                modes.add("fired")
                try:
                    value = float(fired_value)
                except ValueError as exc:
                    raise ValueError(
                        f"{path}:{line_number}: rule firing value must be numeric"
                    ) from exc
                if not math.isfinite(value):
                    raise ValueError(
                        f"{path}:{line_number}: rule firing value must be finite"
                    )
                grouped[ts]["fired"].append(value)
                continue

            flow_value = next(
                (row[key] for key in (
                    "new_flows", "sentinel_new_flows", "new_flows_per_second",
                ) if row.get(key) not in (None, "")),
                None,
            )
            if flow_value is None:
                raise ValueError(
                    f"{path}:{line_number}: expected rule_fired or new_flows column"
                )
            modes.add("new_flows")
            try:
                value = float(flow_value)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{line_number}: new-flow value must be numeric"
                ) from exc
            if not math.isfinite(value):
                raise ValueError(
                    f"{path}:{line_number}: new-flow value must be finite"
                )
            grouped[ts]["new_flows"].append(value)

    if len(modes) > 1:
        raise ValueError(f"{path}: use either rule_fired or new_flows, not both")
    if not modes:
        raise ValueError(f"{path}: no rule samples found")

    samples = []
    for ts, values in sorted(grouped.items()):
        if values["fired"]:
            samples.append((ts, max(values["fired"]) > 0))
        elif values["new_flows"]:
            samples.append((ts, sum(values["new_flows"])))

    if samples and isinstance(samples[0][1], bool):
        return samples

    fired_samples = []
    for index, (ts, value) in enumerate(samples):
        if index < 2:
            fired_samples.append((ts, False))
            continue
        previous_two = samples[index - 2:index]
        consecutive = all(
            0.5 <= later[0] - earlier[0] <= 1.5
            for earlier, later in zip(previous_two + [(ts, value)],
                                      previous_two[1:] + [(ts, value)])
        )
        fired_samples.append((ts, consecutive and all(
            sample[1] > 30 for sample in previous_two + [(ts, value)]
        )))
    return fired_samples


def first_rule_firing(samples, label):
    return next(
        (ts for ts, fired in samples
         if label["t_start"] <= ts <= label["t_end"] and fired),
        None,
    )


def classification(result, attack, available=True):
    if not available:
        return "unavailable"
    if attack:
        return "detected" if result else "missed"
    return "false_positive" if result else "no_false_positive"


def build_detection_rows(labels, audit_events, rule_samples):
    rows = []
    for label in labels:
        if label["scenario"] not in CORE_SCENARIOS:
            continue
        attack = is_attack_type(label["label"])
        events = run_events(audit_events, label)
        detections = [
            event for event in events
            if is_attack_type(event.get("type"))
            and (not attack or type_matches(event.get("type"), label["label"]))
        ]
        detection = detections[0] if detections else None
        rule_time = first_rule_firing(rule_samples, label) if rule_samples is not None else None
        rows.append({
            "run_id": label["run_id"],
            "scenario": label["scenario"],
            "label": label["label"],
            "ml_result": classification(detection, attack),
            "ml_detected": "" if detection is None else 1,
            "rule_result": classification(rule_time, attack, rule_samples is not None),
            "rule_fired": "" if rule_samples is None else int(rule_time is not None),
        })
    return rows


def build_timing_rows(labels, audit_events):
    rows = []
    for label in labels:
        if not is_attack_type(label["label"]):
            continue
        events = run_events(audit_events, label)
        detections = [
            event for event in events
            if type_matches(event.get("type"), label["label"])
        ]
        detection = detections[0] if detections else None
        mitigation = next(
            (event for event in detections if successful_action(event)),
            None,
        )
        recoveries = []
        if detection:
            recoveries = [
                event for event in audit_events
                if event["_ts"] > label["t_end"]
                and event.get("switch") == detection.get("switch")
                and str(event.get("port")) == str(detection.get("port"))
                and is_release(event)
                and successful_action(event)
            ]
        recovery = recoveries[0] if recoveries else None
        rows.append({
            "run_id": label["run_id"],
            "scenario": label["scenario"],
            "label": label["label"],
            "detect_s": round(detection["_ts"] - label["t_start"], 3)
            if detection else "",
            "mitigate_after_detect_s": round(
                mitigation["_ts"] - detection["_ts"], 3
            ) if detection and mitigation else "",
            "recover_after_attack_s": round(
                recovery["_ts"] - label["t_end"], 3
            ) if recovery else "",
        })
    return rows


def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        return ""
    position = (len(ordered) - 1) * fraction
    low, high = int(position), min(int(position) + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def read_ping_log(path):
    grouped = defaultdict(list)
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not {"run_id", "success"} <= set(reader.fieldnames):
            raise ValueError(f"{path}: expected run_id and success columns")
        for line_number, row in enumerate(reader, 2):
            run_id = row.get("run_id", "").strip()
            if not run_id:
                raise ValueError(f"{path}:{line_number}: run_id must not be empty")
            try:
                timestamp(row["ts"])
            except (KeyError, ValueError) as exc:
                raise ValueError(f"{path}:{line_number}: missing or invalid ts") from exc
            success_value = normalize(row["success"])
            if success_value not in TRUE_VALUES | FALSE_VALUES:
                raise ValueError(
                    f"{path}:{line_number}: success must be a boolean or 0/1"
                )
            success = success_value in TRUE_VALUES
            latency = row.get("latency_ms", "")
            try:
                latency = float(latency) if latency else None
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{line_number}: latency_ms must be numeric"
                ) from exc
            if latency is not None and (not math.isfinite(latency) or latency < 0):
                raise ValueError(
                    f"{path}:{line_number}: latency_ms must be finite and non-negative"
                )
            grouped[run_id].append((success, latency))
    return grouped


def build_ping_rows(ping_runs):
    rows = []
    for run_id, samples in sorted(ping_runs.items()):
        latencies = [latency for success, latency in samples
                     if success and latency is not None]
        successes = sum(success for success, _ in samples)
        rows.append({
            "run_id": run_id,
            "probes": len(samples),
            "successes": successes,
            "loss_pct": round(100 * (len(samples) - successes) / len(samples), 2),
            "median_latency_ms": round(statistics.median(latencies), 3)
            if latencies else "",
            "p95_latency_ms": round(percentile(latencies, 0.95), 3)
            if latencies else "",
        })
    return rows


def write_csv(path, rows, columns):
    with path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def build_timing_summary(rows):
    by_scenario = defaultdict(list)
    for row in rows:
        by_scenario[row["scenario"]].append(row)
    columns = ("detect_s", "mitigate_after_detect_s", "recover_after_attack_s")
    summary = []
    for scenario, scenario_rows in sorted(by_scenario.items()):
        record = {"scenario": scenario, "runs": len(scenario_rows)}
        for column in columns:
            observed = [float(row[column]) for row in scenario_rows if row[column] != ""]
            record[column.replace("_s", "_median_s")] = round(
                statistics.median(observed), 3
            ) if observed else ""
        summary.append(record)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, default=Path("data/labels.jsonl"))
    parser.add_argument("--audit", type=Path, default=Path("logs/audit.jsonl"))
    parser.add_argument(
        "--rule-samples", type=Path,
        help="CSV with ts and rule_fired, or ts and per-switch new_flows samples",
    )
    parser.add_argument(
        "--ping-log", type=Path,
        help="optional CSV with run_id, success, and latency_ms columns",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args(argv)

    required = (args.labels, args.audit)
    for path in required:
        if not path.is_file():
            parser.error(f"required input does not exist: {path}")
    for path in (args.rule_samples, args.ping_log):
        if path is not None and not path.is_file():
            parser.error(f"input does not exist: {path}")

    try:
        labels = read_labels(args.labels)
        audit = read_audit(args.audit)
        rules = read_rule_samples(args.rule_samples) if args.rule_samples else None
        detections = build_detection_rows(labels, audit, rules)
        timings = build_timing_rows(labels, audit)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        write_csv(
            args.output_dir / "ml_vs_rule.csv", detections,
            ("run_id", "scenario", "label", "ml_result", "ml_detected",
             "rule_result", "rule_fired"),
        )
        write_csv(
            args.output_dir / "timing.csv", timings,
            ("run_id", "scenario", "label", "detect_s",
             "mitigate_after_detect_s", "recover_after_attack_s"),
        )
        write_csv(
            args.output_dir / "timing_summary.csv", build_timing_summary(timings),
            ("scenario", "runs", "detect_median_s",
             "mitigate_after_detect_median_s", "recover_after_attack_median_s"),
        )
        if args.ping_log:
            ping_rows = build_ping_rows(read_ping_log(args.ping_log))
            write_csv(
                args.output_dir / "collateral_damage.csv", ping_rows,
                ("run_id", "probes", "successes", "loss_pct",
                 "median_latency_ms", "p95_latency_ms"),
            )
    except (OSError, ValueError) as exc:
        print(f"evaluation failed: {exc}", file=sys.stderr)
        return 2

    print(f"Wrote evaluation tables to {args.output_dir}")
    if rules is None:
        print("Rule results are unavailable; rerun with --rule-samples to compare the baseline.")
    if not args.ping_log:
        print("Collateral-damage results are unavailable; rerun with --ping-log for S10 probes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
