import csv
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from evaluate import (
    build_detection_rows,
    build_ping_rows,
    build_timing_rows,
    main,
    read_ping_log,
    read_rule_samples,
)


class EvaluateTests(unittest.TestCase):
    def test_computes_three_sample_rule_from_per_switch_rates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.csv"
            with path.open("w", newline="", encoding="utf-8") as target:
                writer = csv.writer(target)
                writer.writerow(("ts", "switch", "new_flows"))
                for ts, first, second in (
                    (100, 16, 16),
                    (101, 20, 20),
                    (102, 16, 16),
                    (103, 0, 0),
                ):
                    writer.writerow((ts, "s1", first))
                    writer.writerow((ts, "s2", second))

            self.assertEqual(
                read_rule_samples(path),
                [(100.0, False), (101.0, False), (102.0, True), (103.0, False)],
            )

    def test_uses_recorded_rule_firing_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.csv"
            path.write_text("ts,rule_fired\n100,0\n101,1\n", encoding="utf-8")
            self.assertEqual(read_rule_samples(path), [(100.0, False), (101.0, True)])

    def test_builds_detection_and_timing_from_audit_events(self):
        labels = [
            {
                "run_id": "S6_1", "scenario": "S6", "label": "flood",
                "attacker": "of:1:1", "t_start": 100.0, "t_end": 110.0,
            },
            {
                "run_id": "S1_1", "scenario": "S1", "label": "normal",
                "attacker": None, "t_start": 200.0, "t_end": 210.0,
            },
        ]
        events = [
            {"_ts": 102.0, "switch": "of:1", "port": "1",
             "type": "flood", "action": "observe", "onos_status": "ok"},
            {"_ts": 103.0, "switch": "of:1", "port": "1",
             "type": "flood", "action": "meter", "onos_status": "installed"},
            {"_ts": 112.0, "switch": "of:1", "port": "1",
             "type": "flood", "action": "release", "onos_status": "removed"},
        ]
        rules = [(105.0, True)]

        detections = build_detection_rows(labels, events, rules)
        self.assertEqual(detections[0]["ml_result"], "detected")
        self.assertEqual(detections[0]["rule_result"], "detected")
        self.assertEqual(detections[1]["ml_result"], "no_false_positive")
        self.assertEqual(detections[1]["rule_result"], "no_false_positive")

        timings = build_timing_rows(labels, events)[0]
        self.assertEqual(timings["detect_s"], 2.0)
        self.assertEqual(timings["mitigate_after_detect_s"], 1.0)
        self.assertEqual(timings["recover_after_attack_s"], 2.0)

    def test_aggregates_ping_loss_and_latency(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ping.csv"
            path.write_text(
                "run_id,ts,success,latency_ms\n"
                "S10_1,100,true,10\n"
                "S10_1,101,false,\n"
                "S10_1,102,1,20\n",
                encoding="utf-8",
            )
            result = build_ping_rows(read_ping_log(path))[0]
            self.assertEqual(result["loss_pct"], 33.33)
            self.assertEqual(result["median_latency_ms"], 15.0)
            self.assertEqual(result["p95_latency_ms"], 19.5)

    def test_cli_writes_tables_from_saved_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            labels = root / "labels.jsonl"
            labels.write_text(json.dumps({
                "run_id": "S4_1", "scenario": "S4", "label": "flood",
                "attacker": "of:1:1", "t_start": 100, "t_end": 110,
            }) + "\n", encoding="utf-8")
            audit = root / "audit.jsonl"
            audit.write_text(json.dumps({
                "ts": 102, "switch": "of:1", "port": "1", "type": "flood",
                "action": "drop_rule", "onos_status": "installed",
            }) + "\n", encoding="utf-8")
            rules = root / "rules.csv"
            rules.write_text("ts,rule_fired\n105,1\n", encoding="utf-8")
            output = root / "results"

            with redirect_stdout(StringIO()):
                code = main([
                    "--labels", str(labels), "--audit", str(audit),
                    "--rule-samples", str(rules), "--output-dir", str(output),
                ])

            self.assertEqual(code, 0)
            with (output / "ml_vs_rule.csv").open(newline="", encoding="utf-8") as source:
                row = next(csv.DictReader(source))
            self.assertEqual(row["ml_result"], "detected")
            self.assertEqual(row["rule_result"], "detected")
            self.assertTrue((output / "timing_summary.csv").is_file())


if __name__ == "__main__":
    unittest.main()
