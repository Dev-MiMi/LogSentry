# Feature 5: possible brute-force attacks

The new `detect_brute_force_attacks(events, settings)` function in
`logsentry/detection.py` looks for rapid failed-login attempts. Feature 4 counts
failures across the whole imported file; Feature 5 adds a time requirement.
The defaults are **five failures within five minutes**, including exactly five
minutes. The thresholds and window come from `DetectionSettings`.

## How the window moves

Take this sequence from one IP on one host:

```text
09:00:00  failure 1
10:00:00  failure 2
10:00:10  failure 3
10:00:20  failure 4
10:00:30  failure 5
10:00:40  failure 6
```

The first group, failures 1 through 5, takes an hour and 30 seconds. No alert.
The next group, failures 2 through 6, takes 40 seconds. That group qualifies.
This is why checking only the first five attempts is insufficient.

## Follow the code

1. Keep only `failed_login` events and group them by `(hostname, source_ip)`.
2. Sort each group by timestamp, then source line number for tied timestamps.
3. Move `start` through every position with enough failures remaining.
4. Calculate `end = start + threshold - 1`. With five attempts, the last event
   is four positions after the first because Python counts positions from zero.
5. Subtract the first event's timestamp from the last event's timestamp.
6. If the duration fits the configured window, return a High alert containing
   that group as evidence. List every username attempted within the group.

The central calculation is:

```python
duration = ordered[end].timestamp - ordered[start].timestamp
if duration > settings.brute_force_window:
    continue
```

`continue` skips a slow group and tries the next one. With sorted timestamps,
checking each group of five consecutive attempts finds any five-attempt burst.
We compare endpoints before slicing the evidence, so we do not copy a list for
every unsuccessful check. Sorting is the most expensive step; the window checks
then move through each group once.

## Try the sample

From the project directory, run `python3`, then enter:

```python
from logsentry.config import DetectionSettings
from logsentry.parser import read_system_logs
from logsentry.detection import detect_brute_force_attacks

settings = DetectionSettings(year=2026)
parsed = read_system_logs("samples/auth.log", settings)
alerts = detect_brute_force_attacks(parsed.events, settings)

print(len(alerts))                 # 1
print(alerts[0].severity)          # High
print(alerts[0].source_ip)         # 203.0.113.42
print(len(alerts[0].evidence))     # 5
print(alerts[0].description)
```

The description reports five failures within **0:01:08**. Evidence comes from
sample lines 4 through 8; it does not include the subsequent successful login.

## Policy and limits

- Host/IP pairs stay separate. Multiple account names for the same pair count
  together because an attacker may try different accounts.
- A successful login does not erase failures. This rule describes the attempt
  pattern; account-compromise correlation will be a separate rule.
- The rule returns **one alert per host/IP per import**, using the first matching
  group. This avoids overlapping alerts, but later independent bursts in the
  same import do not produce additional alerts yet.
- Invalid-user notices do not count as a second failure. Actual failed-login
  events for invalid users do count.
- A High priority means this pattern deserves investigation. Mistyped passwords,
  shared source IPs, or broken automation can trigger it; it is not confirmation
  of an attack or successful compromise.
- Duplicate records are still counted separately. Import deduplication will
  need its own policy. Rejected log lines remain visible in `parsed.issues`.

The rule returns alerts and never blocks an IP, saves a report, or changes the
input events. No database or Django page is required to use it.

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

Checks cover the real sample, later bursts, exact time boundaries, custom
settings, isolated hosts/IPs, harmless slow attempts, input ordering, malformed
records, and the one-alert-per-source policy.
