# Reviewed lab evidence

These four selected screenshots show verified setup steps using fictional identities and
isolated lab addresses. They were reviewed for visible passwords, recovery
answers, tokens, and private installer output before being selected as candidate
GitHub evidence. Recheck each image before publication if lab details change.

| Image | What it shows | Limitation |
| --- | --- | --- |
| [dc-ou.png](dc-ou.png) | `corp.example.test` and the lab OU structure | Does not prove GPO configuration. |
| [ws-dns2.png](ws-dns2.png) | WS01 resolving the domain controller's AD DNS SRV record | Captured before the successful domain-user logon. |
| [ws-check.png](ws-check.png) | `CORP\analyst1` on WS01 receiving HTTP 200 from the internal service desk | Does not prove access is restricted to one port. |
| [siem-status3.png](siem-status3.png) | Wazuh installer completion and active manager, indexer, and dashboard services | Does not prove agent enrollment or event ingestion. |

Only the listed images are allowlisted in this project's `.gitignore`.
The raw firewall console screenshot stays local because it includes interface
and certificate details. Document the topology in text until sanitized network
rule evidence is ready.
