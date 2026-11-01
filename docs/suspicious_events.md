# Feature 2: invalid users and success after failures

This change adds two rules to `logsentry/detection.py`. Call
`detect_suspicious_events(events, settings)` to run both, or call each separately.
They return Alert records without reading files, changing accounts, or saving
reports. Rules for repeated failures, timed brute-force bursts, and unexpected
login hours/networks remain separate.

## Expected results for the sample

| Pattern | Result | Evidence |
| --- | --- | --- |
| Five failures for Bob, then Bob succeeds from the same IP/host | High: success_after_failures | Lines 4-9 |
| Invalid user admin notice and failed-password record | Medium: invalid_user | Lines 10-11 |
| Alice's successful logins without matching failures | No finding from these two rules | Checked by Feature 6 separately |

The High finding suggests possible compromise requiring investigation. A user
can legitimately mistype a password and then succeed. It is not confirmation of
an attack, so it does not automatically receive Critical severity.

## Rule A: invalid account names

`detect_invalid_user_attempts` finds either an `invalid_user` event or a
`failed_login` event whose `invalid_user` field is True. It groups evidence by
host, source IP, and username, returning one finding for each group per import.

SSH often records both an invalid-user notice and the subsequent password
failure for one attempt. We keep both records in one finding and do not claim
that the number of records equals the number of attempts. A failed-password
record mentioning an invalid user is enough even if the separate notice is absent.
Ordinary failed logins for valid users are not invalid-user findings.

## Rule B: successful login after repeated failures

`detect_success_after_failures` sorts events by timestamp and then line number.
For tied timestamps, their original line order determines whether a failure
preceded the successful login. Every event is matched by:

```python
key = (event.hostname, event.source_ip, event.username)
```

That key is essential: Bob's failures must not be attached to Alice's login,
nor to activity on another machine or from a different source. The default
requires three failures within the ten minutes preceding a successful login.
Exactly ten minutes qualifies; an older failure is excluded. The threshold is
`settings.repeated_threshold`, and the window is
`settings.success_after_failures_window`.

The function keeps a queue of failures for each key:

1. Remove failures older than the configured window.
2. If the current event is a failure, append it to that queue.
3. If the current event is a success and enough failures remain, create a High
   alert containing the failures and the successful event.
4. Clear the queue after every success, even when no alert was generated.

The last step prevents reusing old failures for each subsequent success. A new
sequence of failures may still produce another finding. A success for Alice
only resets Alice's key; it does not clear Bob's failures.

`deque` is Python's queue type. `.append(event)` adds a failure at the end,
`.popleft()` removes the oldest failure, and `.clear()` empties that account's
history. Expired entries are removed as matching events arrive; all state is
local to this batch and is discarded when the function returns.

Evidence is assembled with:

```python
evidence = tuple(recent) + (event,)
```

`tuple(recent)` preserves the remaining failure events. `(event,)` is a tuple
containing the success; the plus joins them. The failures themselves stay in
chronological order, and original raw lines/line numbers remain in each event.

## Why two rules may describe the same login

Bob's success can produce both a Feature 2 finding for success after failures
and a Feature 6 finding for an untrusted source. They answer different questions
and preserve their respective evidence. Future incident reports can group these
related alerts; the current detectors do not merge them into a single incident.

This rule checks successes using password or public-key authentication. A
public-key success after password failures is a correlation to review, not
evidence that a password was guessed. Authentication methods remain in the
evidence. Invalid-account failures are excluded from success correlation because
they do not establish a failure of an existing account's credentials.

## Run the sample yourself

Start Python **from the project directory**, not inside `logsentry/`:

```bash
cd /root/LogSentry
python3
```

Then enter:

```python
from logsentry.config import DetectionSettings
from logsentry.parser import read_system_logs
from logsentry.detection import detect_suspicious_events

settings = DetectionSettings(year=2026)
parsed = read_system_logs("samples/auth.log", settings)
alerts = detect_suspicious_events(parsed.events, settings)

for alert in alerts:
    print(alert.rule, alert.severity, alert.usernames)
    print(alert.description)
    print("Evidence lines:", [event.line_number for event in alert.evidence])
```

Expect two findings: High for Bob's success and Medium for invalid user admin.
The combined detector materializes input once so both rules also work when
their input is a one-use iterator or generator.

## Scope and validation

Correlation is limited to this imported batch. It does not carry history across
files, resolve renamed accounts, identify a person behind a shared IP, or prove
the log source is authentic. The parser normalizes IPs before detection.
Rejected input remains in `parsed.issues`; duplicated valid records still count.
One invalid-account group may contain several genuine attempts, but the finding
does not infer an attempt count from overlapping SSH message types.

Run all checks from the project directory:

```bash
python3 -m unittest discover -s tests -v
```

The new checks cover the sample, each matching field, threshold/window
boundaries, expired and future failures, ordering, resets after success, new
failure sequences, invalid-account evidence, missing fields, and malformed logs.
