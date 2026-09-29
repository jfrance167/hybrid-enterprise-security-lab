# Reviewed lab evidence

These four selected screenshots show verified setup and control tests using fictional identities and
isolated lab addresses. They were reviewed for visible passwords, recovery
answers, tokens, and private installer output before being selected as candidate
GitHub evidence. Recheck each image before publication if lab details change.

| Image | What it shows | Limitation |
| --- | --- | --- |
| [dc-ou.png](dc-ou.png) | `corp.example.test` and the lab OU structure | Does not prove GPO configuration. |
| [ws-dns2.png](ws-dns2.png) | WS01 resolving the domain controller's AD DNS SRV record | Captured before the successful domain-user logon. |
| [siem-status3.png](siem-status3.png) | Wazuh installer completion and active manager, indexer, and dashboard services | Does not prove agent enrollment or event ingestion. |
| [siem-agent-cutover.png](siem-agent-cutover.png) | Four active Wazuh agents, rule `100101` under `LAB-FW`, and no UDP 514 listener after cutover | A point-in-time sample; does not prove retention or continuous availability. |

Only the listed images are allowlisted in this project's `.gitignore`.
Other raw console screenshots remain local and ignored. The new image
was selected from clean console output and contains only fictional names and
isolated lab addresses; do not commit full config exports or raw logs.
