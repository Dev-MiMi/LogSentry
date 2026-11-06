"""Rule catalogue and investigation advice shared by the UI and verification."""

RULES = {
    "110000": (3, "Informational", "Collected activity", "Check the source and original message. Activity alone does not establish an authentication event or attack."),
    "110001": (3, "Informational", "Package activity", "Check the package operation against expected installation or maintenance work."),
    "110010": (5, "Low", "SSH authentication failure", "Check the account and source IP. One failure may be a typing error; inspect nearby events."),
    "110011": (5, "Low", "Unknown SSH account", "Check whether the username was mistyped. Look for repeated attempts from this source."),
    "110012": (3, "Informational", "Successful SSH login", "Confirm the account, source IP and authentication method are expected."),
    "110013": (7, "Medium", "Privileged SSH login", "Confirm that the root login was authorized. A privileged login is not automatically a compromise."),
    "110020": (8, "Medium", "Repeated SSH failures", "Compare original times and distinct event IDs. Check for mistyped credentials, delivery backlog or replay."),
    "110021": (10, "High", "Possible SSH brute force", "Investigate distinct attempts from this IP on this host. Check original times before interpreting a delivery burst as an attack."),
    "110022": (12, "High", "SSH success after failures", "Confirm failures preceded this success for the same account and IP. Verify with the account owner before concluding compromise."),
}


def rule_catalogue():
    return [{"id": key, "level": value[0], "severity": value[1], "title": value[2], "guidance": value[3]}
            for key, value in RULES.items()]


def event_rules(document):
    """Candidates only: Wazuh owns correlation and final rule selection."""
    event = document["logsentry"]
    kind = event.get("ssh", {}).get("kind")
    if kind == "failed_login":
        ids = ("110010", "110020", "110021")
    elif kind == "invalid_user":
        ids = ("110011",)
    elif kind == "successful_login":
        ids = ("110012", "110013", "110022") if event["ssh"]["username"] == "root" else ("110012", "110022")
    else:
        ids = ("110001",) if event["event_type"] == "package_activity" else ("110000",)
    return [rule for rule in rule_catalogue() if rule["id"] in ids]
