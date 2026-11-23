# Mitigation engine: test results

Full pipeline in the `mininet` VM: ONOS 2.7 + Mininet (`topo/lab_topo.py --link-s3`) + ML detector + engine.
Branch `abdou` at `8ed3fd7`, tested 2026-11-22. The attacker is h1 (switch s1, port 1). Times are seconds after the engine's first action.

## Summary

| Scenario | Attack | First action | Blocked on | Released | Collateral (h2 → h5 ping) |
|---|---|---|---|---|---|
| S4 flood | 80 pkt/s for 60 s | meter 2 pkt/s | s1:1 only | +52.9 s, auto | 0% loss |
| S5 slow flood | 8 pkt/s for 60 s | meter + flag_human (`unknown`) | s1:1 only | +55.5 s, auto | 0% loss |
| S6 pulsed flood | 80 pkt/s, 2 s on / 6 s off, 90 s | meter 2 pkt/s | s1:1 only | +89.3 s, auto | 0% loss |
| S7 spoofing | h1 sends as h6, 45 s | drop_mac | s1:1 only | +59.9 s, auto | 0% loss |

Every attack was detected, mitigated on the attacker's port only, and released only after the attack stopped.
Engine log: 0 errors.

## How to read the tables

- **meter**: the port is limited to 2 pkt/s. This is the first answer to a flood.
- **drop**: if the detector still reports the port 15 s later, the meter becomes a drop rule.
- **sample**: the drop rule's counter showed 200 packets or fewer in 6 s (`dropped_per_check`), so the engine replaces it with an 8 pkt/s meter to the controller. That lets it see what the port is sending.
- **reblock**: while sampling, more than 5 new hosts (MAC addresses) showed up on that port in 3 s, on 2 checks in a row (`new_hosts_per_check`). The attack is still running, so the drop rule goes back.
- **release:auto**: 3 calm checks in a row, so all rules on the port are removed. No timer is involved; the decision comes from the switch counters.
- **spoofed_per_check**: packets the MAC-drop rule matched during one check. 0 means the attacker stopped using the victim's MAC.
- **refused:duplicate**: the detector resends its alert every 10 s. The port is already mitigated, so the engine ignores the repeats.
- `dropped_per_check` is the packet count scaled to one 6 s check, from the rule's packet counter in ONOS.
- **Collateral**: h2 pings h5 during the attack. The traffic crosses s1-s2-s3 but not h1's port, so 0% loss means innocent hosts were not affected.

## Timelines

### S4 flood: 80 pkt/s, 60 s

| Time | Type | Action | Measurement |
|---|---|---|---|
| +0.0 s | flood | meter | |
| +18.6 s | flood | drop | detector still reported the port after 15 s |
| +23.0 s | flood | sample | dropped_per_check=0.0 |
| +32.7 s | flood | reblock | new_hosts_per_check=24 |
| +41.3 s | flood | sample | dropped_per_check=96.6 |
| +52.9 s | flood | release:auto | new_hosts_per_check=0 |

5 repeated detector alerts were refused as duplicates.

**What happened:**
- The meter slowed the flood. The detector kept reporting the port, so it became a drop rule after the 15 s escalation.
- The first sample came early: ONOS reports a new rule's counter about one poll late, so the first reading looked calm (0.0).
- Sampling then saw 24 new fake MACs per check, which is clearly an attack, so the engine re-blocked.
- When the flood ended, the next sample saw 0 new hosts on 3 checks, and the engine released.

### S5 slow flood: 8 pkt/s, 60 s

| Time | Type | Action | Measurement |
|---|---|---|---|
| +0.0 s | unknown | meter + flag_human | |
| +20.2 s | slow_exhaustion | meter (upgrade) | |
| +31.0 s | slow_exhaustion | sample | dropped_per_check=35.9 |
| +55.5 s | slow_exhaustion | release:auto | new_hosts_per_check=0 |

5 repeated detector alerts were refused as duplicates.

**What happened:**
- At 8 pkt/s the detector first wasn't sure which attack it was, so it reported `unknown`. The engine applied a meter and flagged the port for a human.
- About 20 s later the detector named it `slow_exhaustion`. The engine upgraded the mitigation to that playbook.
- The slow flood stays under the 200-packet block threshold (35.9 per check), so the engine went to sampling.
- After the attack ended, 3 calm checks released the port.

### S6 pulsed flood: 80 pkt/s, 2 s on / 6 s off, 90 s

| Time | Type | Action | Measurement |
|---|---|---|---|
| +0.0 s | flood | meter | |
| +18.1 s | flood | drop | |
| +20.2 s | flood | sample | dropped_per_check=106.1 |
| +29.3 s | flood | reblock | new_hosts_per_check=13 |
| +38.5 s | flood | sample | dropped_per_check=67.7 |
| +61.2 s | flood | reblock | new_hosts_per_check=12 |
| +69.9 s | flood | sample | dropped_per_check=131.2 |
| +89.3 s | flood | release:auto | new_hosts_per_check=0 |

11 repeated detector alerts were refused as duplicates.

**What happened:**
- This is the hardest case: the attacker pauses to look calm.
- Each time the engine sampled during a burst, it saw 12–13 new hosts per check and re-blocked. This happened twice.
- The release came at +89.3 s, about when the 90 s attack ended. This is why the engine waits for 3 calm checks: with a timer, the port would have been released in the middle of the attack.

### S7 spoofing: h1 sends as h6, 45 s

| Time | Type | Action | Measurement |
|---|---|---|---|
| +0.0 s | spoofing | drop_mac | |
| +59.9 s | spoofing | release:auto | spoofed_per_check=0.0 |

3 repeated detector alerts were refused as duplicates.

**What happened:**
- The engine dropped only frames that come from h1's port and carry h6's MAC. h1's normal traffic and the real h6 kept working.
- The rule stayed while its counter kept growing, which means the spoofing was still running.
- After the attack, the counter stopped growing (0.0 per check). After 3 calm checks the rule was removed.
- The engine also purged the forwarding flows that ONOS had learned for h6's MAC, so h6 was reachable again right away.

## Automated checks

| Check | Command | Result |
|---|---|---|
| Offline test (fake ONOS) | `./start-mitigation.sh test` | ok: 66 audit lines, all guardrails, playbooks, release checks and API behave |
| Live check (real ONOS + Mininet) | `./start-mitigation.sh live-check` | 50/50 passed |

- The **offline test** runs the engine against a fake ONOS with a simulated clock, so it takes seconds. It covers the release cycle, the guardrails (switch-to-switch ports, duplicates, 5 actions per minute), upgrades, `/pin`, dry run, metrics and the HTTP API.
- The **live check** sends real attacks in Mininet without the detector, posting alerts to the engine directly. It checks that rules really appear in ONOS and that other hosts keep working. It also checks that every rule and meter is gone after the release.
