# Reviewed lab evidence

These six selected screenshots show verified setup and control tests using fictional identities and
isolated lab addresses. They were reviewed for visible passwords, recovery
answers, tokens, and private installer output before being selected as candidate
GitHub evidence. Recheck each image before publication if lab details change.

| Image | What it shows | Limitation |
| --- | --- | --- |
| [dc-ou.png](dc-ou.png) | `corp.example.test` and the lab OU structure | Does not prove GPO configuration. |
| [ws-dns2.png](ws-dns2.png) | WS01 resolving the domain controller's AD DNS SRV record | Captured before the successful domain-user logon. |
| [ws-check.png](ws-check.png) | `CORP\analyst1` on WS01 receiving HTTP 200 from the internal service desk | Does not prove access is restricted to one port. |
| [siem-status3.png](siem-status3.png) | Wazuh installer completion and active manager, indexer, and dashboard services | Does not prove agent enrollment or event ingestion. |
| [siem-ingestion.png](siem-ingestion.png) | Three active Wazuh agents and one manager alert each from `APP01`, `DC01`, `WS01`, and the firewall | A point-in-time sample; does not prove retention or continuous availability. |
| [firewall-enforcement.png](firewall-enforcement.png) | Zero broad internal pass-to-any rules, scoped Wazuh telemetry allows, and a logged workstation-to-SIEM TCP 443 deny | The workstation source uses a DHCP address; rule hit counts and reboot regression remain to be reviewed. |

Only the listed images are allowlisted in this project's `.gitignore`.
Other raw console screenshots remain local and ignored. The two new images
were selected from clean console output and contain only fictional names and
isolated lab addresses; do not commit full config exports or raw logs.
