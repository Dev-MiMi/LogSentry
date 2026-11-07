# LogSentry roadmap

Updated 7 November 2026 after verified phone-to-PC deployment and clarification
of the project's mobile-app security and crash-event goals.

## Current project goal

Collect security-related events and crash logs from various apps installed on
phones, forward them securely to Wazuh for further processing and analysis, and
review the results through LogSentry's web interface. App integrations must use
event sources and permissions actually available on the phone.

LogSentry stays a web app until the user explicitly requests otherwise. The
dedicated mobile app is the final milestone; it is not started automatically as
part of source integration, deployment or hardening work.

| Milestone | Purpose | Status |
| --- | --- | --- |
| 1. Secure Event API | Authenticate collectors, prevent duplicates and store received events privately. | Complete |
| 2. Reliable Delivery & Deployment Foundation | Collector credentials, offline queues, retries, browser login and deployment files. | Complete |
| 3. Wazuh Integration | Export real receiver events, run the pipeline on the Ubuntu PC and verify exact manager receipt. | Complete for the local testing lab |
| 4. Wazuh Detection Rules | Custom rules, severity mapping, alerts and investigation views. | Complete for the local testing lab: 20/20 Wazuh scenarios; exact real package and SSH alerts verified in the index and authenticated dashboard queries |
| 5. End-to-End Hardening | Verify intended event-source coverage and delivery; test failures, rotation, retention, security and resource limits. | Pending; intended mobile-app security/crash sources need integration and verification first |
| 6. Mobile App | Dedicated Android app for permitted collection of mobile-app security and crash events using the existing API. | Final milestone; pending explicit user instruction to begin |

## Implemented coverage and remaining work

Milestones 1–4 are complete for the implemented local testing pipeline and its
current SSH rules. The [phone-to-PC deployment](phone_to_pc.md) also verified
trusted HTTPS delivery and Wazuh indexing under a separate phone identity.
These results used Termux package/alternatives logs and Debian/proot SSH records;
they do not establish collection or detection of security and crash events from
the intended installed mobile apps.

Before claiming the project's event-collection goal is met, identify the target
apps, their available security/crash sources and required permissions; add any
missing collection/parsing and Wazuh rules; then verify real events from those
apps through the full pipeline. This work continues within the web-app project
and does not introduce a new numbered milestone or begin the mobile app.

Milestone 3's deployment evidence and commands are in
[the local lab guide](local_wazuh_lab.md). Completion means verified delivery to
the manager. It does not mean every event is an alert or searchable in the default
Wazuh dashboard. Milestone 4 subsequently enabled nine custom rules and saved
investigation searches; archive indexing remains disabled.

See [milestone 4 completion evidence](wazuh_detection.md). The immediate focus is
the intended mobile-app event sources, followed by milestone 5's end-to-end
hardening, rotation, retention and broader failure testing. Production deployment,
remote device enrollment, sustained-load testing and retention are not implied
by the completed local lab check.
