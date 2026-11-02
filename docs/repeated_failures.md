# First detection rule: repeated failed logins

The sample calculations in this learning walkthrough use the fictional test
fixture in `tests/fixtures/ssh_auth.log`. The dashboard displays collected system
logs only; see [local collection](local_collection.md) for operational use.

This is Feature 4 of LogSentry. It uses the events from `parser.py`, the
`repeated_threshold` from `config.py`, and the `Alert` record from `data.py`.
It returns findings without reading files, saving reports, or printing output.

## Example behavior

Our policy is three or more failures in the imported file:

| Target host | Source IP | Failed logins | Result |
| --- | --- | --- | --- |
| ubuntu-lab | 203.0.113.42 | 5 | One Medium alert |
| ubuntu-lab | 198.51.100.23 | 1 | No repeated-failure alert |

The severity is an initial policy choice. An alert documents a pattern worth
investigating; it does not establish that an account was compromised.

## Follow the function in `logsentry/detection.py`

1. **Select failures.** `event.event_type == "failed_login"` excludes successful
   logins and unrelated messages. Invalid-user notices do not add an extra
   failure on top of their corresponding failed-login entry.
2. **Group the events.** The dictionary key `(event.hostname, event.source_ip)`
   identifies both the target machine and the source. A tuple is simply a pair
   of values here. Two failures against one host and one against a different
   host do not create a three-failure finding.
3. **Count and compare.** `len(failures)` counts the events for that pair. The
   function skips any group below `settings.repeated_threshold`.
4. **Build an alert.** Its evidence contains the actual events in time order;
   its usernames list includes every account tried from that source.
5. **Return the findings.** The result is a list that a later report or Django
   view can display. Calling the function does not change your input events.

`defaultdict(list)` saves a little bookkeeping: the first use of a new key
creates an empty list. `.append(event)` adds one failed event to that list.

## Try it with your sample

From the project directory, start Python with `python3` and enter:

```python
from logsentry.config import DetectionSettings
from logsentry.parser import read_system_logs
from logsentry.detection import detect_repeated_failed_logins

settings = DetectionSettings(year=2026)
parsed = read_system_logs("tests/fixtures/ssh_auth.log", settings)
alerts = detect_repeated_failed_logins(parsed.events, settings)

print(len(alerts))                   # 1
print(alerts[0].source_ip)           # 203.0.113.42
print(len(alerts[0].evidence))       # 5
print(alerts[0].usernames)           # ('bob',)
print(alerts[0].description)
```

The description says the five failures were observed across the imported log.

## Limits of this rule

This count has no time window. Three failures over three days still produce a
repeated-failure finding. Feature 5 separately determines whether attempts
form a burst within five minutes. See [the brute-force walkthrough](brute_force.md)
for that rule and its High priority.

The input may be incomplete: malformed lines remain in `parsed.issues` and
are not counted. A dashboard must show those issues along with any findings.
Multiple users can share an IP, so repeated failures alone do not identify an
attacker. Reimporting overlapping logs or supplying duplicated event records
will count those records again; import deduplication is a later concern.

Run the automated checks with:

```bash
python3 -m unittest discover -s tests -v
```

They verify the sample result, threshold boundaries, separate hosts/IPs,
multiple accounts, ignored events, incomplete records, and evidence ordering.
