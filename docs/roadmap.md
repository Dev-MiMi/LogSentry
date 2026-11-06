# LogSentry roadmap

Updated 6 November 2026 after deployment on the Ubuntu/Wazuh PC.

| Milestone | Purpose | Status |
| --- | --- | --- |
| 1. Secure Event API | Authenticate collectors, prevent duplicates and store received events privately. | Complete |
| 2. Reliable Delivery & Deployment Foundation | Collector credentials, offline queues, retries, browser login and deployment files. | Complete |
| 3. Wazuh Integration | Export real receiver events, run the pipeline on the Ubuntu PC and verify exact manager receipt. | Complete for the local testing lab |
| 4. Wazuh Detection Rules | Custom rules, severity mapping, alerts and investigation views. | Pending |
| 5. End-to-End Hardening | Broader failure testing, rotation, retention, security and production reliability. | Pending |
| 6. Android Collector | Kotlin app for Android-permitted events sent through the LogSentry API. | Pending |

Milestone 3's deployment evidence and commands are in
[the local lab guide](local_wazuh_lab.md). Completion means verified delivery to
the manager. It does not mean every event is an alert or searchable in the default
Wazuh dashboard. Archive indexing and custom threat rules were not enabled.

The next milestone is **4: Wazuh Detection Rules**. Production deployment,
remote device enrollment, sustained-load testing and retention are not implied
by the completed local lab check.
