# Authorized network-deny triage exercise

This is a safe, fictional analyst exercise using the isolated company lab.
The operator generated connection attempts from the lab workstation to
unapproved management and server ports. No exploit or malware was used.

## Scenario and observations

| Step | Evidence | Analyst interpretation |
| --- | --- | --- |
| Baseline | `WS01` signed into `corp.example.test`; its domain policy update succeeded. Internal service desk returned HTTPS 200 with certificate validation after the TLS change; Wazuh TCP 1514 connected. | Normal business and telemetry flows worked after the allowlist change. |
| Management probe | `WS01` at `10.77.10.139` attempted `SIEM01` at `10.77.30.10:443`. The TCP connection failed. OPNsense recorded `block,in`; Wazuh rule `100100` recorded the source, destination, and port at 2026-09-29 02:43 UTC. | Cross-segment management access was blocked and visible to the SIEM. |
| Server probe | `WS01` attempted `APP01` at `10.77.20.20:22`. The TCP connection failed. OPNsense recorded `block,in` at 2026-09-29 02:55 UTC. | The user's approved web access did not imply SSH access. |
| Independent log-source test | A harmless failed local SSH login to a nonexistent account on `APP01` produced Wazuh rule `5710` at 2026-09-29 03:10 UTC. | The Linux agent ingested a separate authentication event. |
| Firewall agent cutover | After enrolling OPNsense as Wazuh agent `004`, an authorized `APP01` connection attempt to `SIEM01:443` was blocked. Rule `100101` appeared under `LAB-FW` at 2026-09-29 04:19 UTC, after the old UDP 514 target and listener were removed. | The encrypted, authenticated agent path carried a fresh firewall event without the legacy syslog feed. |

## Triage and disposition

1. Confirm the lab source and destination against the asset inventory and
   approved matrix in [FIREWALL_POLICY.md](FIREWALL_POLICY.md).
2. Match the firewall timestamp, action, source, destination, and port with
   Wazuh rule `100100` for the original test or `100101` for the agent-cutover
   test. Distinguish the successful normal flows from the
   intentionally denied probes.
3. Check for any unapproved account or source, repeated attempts, or a later
   successful management connection. The test evidence above does not show
   those conditions; it is an authorized control validation.
4. Close the exercise as an authorized test with the rule unchanged. Escalate
   a comparable unplanned event to the lab operator for investigation and
   preserve its raw evidence privately.

This exercise supports selected ISO/IEC 27001:2022 Annex A controls 8.15
(logging), 8.16 (monitoring), 8.20 (network security), and 8.22 (network
segregation). It demonstrates specific events at specific times, not a mature
24-hour monitoring process or certification. Selected sanitized screenshots
are in [evidence/](evidence/README.md); raw logs and private identifiers are
not published.
