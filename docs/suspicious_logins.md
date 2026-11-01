# Feature 6: suspicious login hours and source IPs

`detect_suspicious_logins(events, settings)` in `logsentry/detection.py` checks
successful logins against two choices in `config.py`:

- Normal hours: **06:00 up to, but excluding, 22:00** by default.
- Trusted source networks: **192.168.1.0/24** by default.

One reason produces a Medium alert. Both reasons produce High. Each flagged
login has its own alert containing the original event as evidence. A legitimate
login can trigger these rules; the finding calls for investigation rather than
asserting the source is an attacker.

## What the sample should do

With the sample's timezone configured as UTC:

| Account | Login time | Source IP | Result |
| --- | --- | --- | --- |
| alice | 09:00:12 | 192.168.1.20 | No alert: expected hours and network |
| bob | 10:16:27 | 203.0.113.42 | Medium: source outside trusted networks |
| alice | 23:45:10 | 198.51.100.77 | High: unusual time and source network |

Bob's login follows failures, but this rule only assesses time and network.
Correlating those failures with the successful account will be a separate rule.

## Follow the function

1. **Prepare settings once.** `ZoneInfo(settings.timezone_name)` represents the
   machine's local clock. `ip_network(...)` interprets each trusted subnet.
2. **Choose successful logins.** Failures and other events belong to other rules.
3. **Check local time.** Convert the UTC timestamp with `astimezone(local_zone)`
   before calling `settings.is_normal_login_hour(local_time.hour)`.
4. **Check the source IP.** Convert it with `ip_address(...)`, then check whether
   it belongs to any configured network. Match address versions first because
   IPv4 sources and IPv6 networks are different families.
5. **Collect reasons.** If neither check flags the login, return no alert for it.
   Otherwise create an Alert with the reasons and original log event.

The severity choice is:

```python
severity="High" if len(reasons) == 2 else "Medium"
```

The main timezone step is:

```python
local_time = event.timestamp.astimezone(local_zone)
```

For example, 21:00 UTC is 22:00 in `Africa/Lagos`. Checking the UTC hour directly
would wrongly treat that login as inside the normal hours. Evidence stays in UTC;
the description includes the local timestamp, offset, and timezone used.
Working hours that cross midnight, such as 22:00-06:00, are supported by config.

## What does /24 mean?

`192.168.1.0/24` describes a subnet covering 192.168.1.0 through 192.168.1.255.
It does not include 192.168.10.20 or 192.168.2.20. Checking a text prefix can get
this wrong; Python's `ipaddress` module handles real network membership.
This policy does not validate that an address is assignable to a host; the
parser validates the address syntax, and this rule checks network membership.

Private addresses outside the configured subnet are still unexpected. You can
explicitly trust a public subnet, an IPv6 subnet, or a single address using
/32 for IPv4 and /128 for IPv6. An empty trusted-networks tuple flags every
successful login's source. It does not disable the source check.
IPv4-mapped IPv6 addresses are interpreted as their IPv4 source, consistently
with the parser. Use IPv4 CIDR settings when trusting those mapped sources.

## Try the sample

Start `python3` from the project directory and enter:

```python
from logsentry.config import DetectionSettings
from logsentry.parser import read_system_logs
from logsentry.detection import detect_suspicious_logins

settings = DetectionSettings(year=2026, timezone_name="UTC")
parsed = read_system_logs("samples/auth.log", settings)
alerts = detect_suspicious_logins(parsed.events, settings)

for alert in alerts:
    print(alert.severity, alert.usernames, alert.source_ip)
    print(alert.description)
```

Expect two alerts: Medium for Bob and High for Alice's late login.
Adjust the policy by constructing different settings, for example:

```python
settings = DetectionSettings(
    year=2026,
    timezone_name="Africa/Lagos",
    trusted_networks=("192.168.1.0/24", "203.0.113.0/24"),
)
```

The timezone must describe the system that produced the legacy log timestamps.
ISO timestamps with explicit offsets already supply their own time reference;
this rule evaluates them against the configured working-hours timezone.

## What this rule does not know yet

Trusted networks and hours are one policy for the input batch, shared by all
hosts and accounts. Individual work schedules, weekends, VPN context, and
per-host policies will need additional configuration later. This is explicit
network matching, not geolocation, an IP reputation feed, or learned behavior.

The function expects parser-validated IPs. A missing source IP is skipped;
an invalid IP supplied directly raises ValueError. Malformed input log records
are listed in `parsed.issues`, which the future report/dashboard must display.
Each duplicate record would produce its own alert; import deduplication is a
separate concern. The function never blocks an IP or changes an account.

## Test the behavior

```bash
python3 -m unittest discover -s tests -v
```

The checks cover the sample, each reason and severity, hour boundaries, local
timezone/date conversion, daylight-saving offsets, night shifts, IPv4/IPv6
subnets, mapped addresses, and expected activity that should produce no alert.
