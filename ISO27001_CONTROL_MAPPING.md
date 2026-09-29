# ISO/IEC 27001:2022 lab control mapping

This mapping connects the fictional lab's risks, selected Annex A controls,
implementation evidence, and gaps. It is a lab-specific working Statement of
Applicability excerpt, not a complete organizational ISMS or certification
claim. ISO/IEC 27001 requires risk assessment and treatment, a scoped
Statement of Applicability, and continuing review. A service or screenshot
alone does not establish conformity.

## Scope and risk decisions

The scope is the five isolated VirtualBox VMs, their internal networks, the
fictional `corp.example.test` domain, the internal service desk, OPNsense,
and Wazuh. Public GitHub source and selected sanitized screenshots are in
scope for evidence handling. The user's real accounts, devices, school, and
employer are outside scope. The lab operator is the control and risk owner.

| Risk | Treatment decision | Acceptance condition |
| --- | --- | --- |
| Lateral movement from a user endpoint | Segment users, servers, and management; allow documented services; deny and log other routed flows. | Positive domain/app/agent tests and two negative port tests passed after replacing broad rules. |
| Exposure of credentials or private telemetry | Keep private configs and logs outside Git, scan public history, review screenshots. | Public tree and alert queues checked before release. |
| Missing or altered security events | Verify source enrollment, event arrival, time synchronization, retention, and protected access. | Linux, both Windows agents, and firewall alerts reached Wazuh. Time, retention, access review, and longer storage observation remain open. |
| Insecure lab-only services | Isolate HTTP and self-signed management endpoints; schedule TLS/auth improvement. | Risk remains open until TLS and access restrictions are tested. |
| Unapplied operating-system security updates | Inventory pending updates, patch during a maintenance window, and verify service recovery. | `APP01` and `SIEM01` reported pending security updates; record patch result and exceptions privately. |
| Unauthenticated firewall log forwarding | Restrict sender and listener to the isolated management network; replace UDP Syslog with authenticated TLS before production use. | Packet delivery and a Wazuh deny alert were verified, but the lab transport is unencrypted. |

## Selected controls and evidence status

| ISO/IEC 27001:2022 Annex A control | Why selected | Current evidence | Status / next test |
| --- | --- | --- | --- |
| 5.9 Inventory of information and other associated assets | Identify systems and owners before setting rules. | Five-VM inventory and address plan in `README.md`. | **Partial:** record OS versions, owner, data class, and review date. |
| 5.15 Access control | Limit access to domain, network services, and management. | Synthetic standard account and domain join documented. | **Partial:** test role restrictions and management access. |
| 8.8 Management of technical vulnerabilities | Identify and remediate exposed packages. | `APP01` reports pending updates at console login. | **Open:** patch, reboot if required, and verify service and event collection. |
| 8.15 Logging | Preserve useful security event records. | `APP01`, `DC01`, and `WS01` agents active with alerts; OPNsense deny produced Wazuh rule `100100`. Offline ext4 check found no structural errors; fresh events arrived after the direct VT-x recovery. | **Partial:** confirm time, retention, access protection, and longer storage stability. |
| 8.16 Monitoring activities | Review events and respond to anomalies. | Linux sudo and failed SSH, Windows logon/assessment, and firewall-deny alerts reached the manager; `INCIDENT_EXERCISE.md` records one authorized triage and disposition. | **Partial:** define review cadence and test an unplanned-event escalation. |
| 8.20 Networks security | Control and observe traffic between networks. | Four broad passes disabled; `pfctl` showed zero internal pass-to-any rules. App, AD DNS, policy update, and Wazuh telemetry succeeded; dashboard TCP 443 and app TCP 22 failed and were logged. | **Partial:** reserve the workstation address, test all AD ports, and review rule hits after reboot. |
| 8.21 Security of network services | Define security needs for DNS, AD, web, telemetry, and update access. | Named port matrix in `FIREWALL_POLICY.md`, Wazuh Syslog bound to the management address and limited to the firewall IP. | **Open:** internal HTTP and UDP Syslog lack TLS; dashboard/API listeners remain bound to the guest interface and depend on firewall policy. |
| 8.22 Segregation of networks | Keep users, servers, and management in separate zones. | Three internal networks; routed users-to-management dashboard access denied and logged. | **Partial:** add host firewall controls for `APP01` and `DC01`, which share one subnet. |
| 8.32 Change management | Make changes reviewable and reversible. | Reviewed scripts create private dated OPNsense backups; reload and positive/negative results are recorded in `FIREWALL_POLICY.md`. | **Partial:** retain a private change record and perform reboot regression tests. |

Status is evidence based: **open** means a known risk remains; **pending**
means no adequate test is recorded; **partial** means one part is shown but the
control is not fully demonstrated. A claim that the lab "follows ISO 27001"
should link to this mapping and disclose these statuses. No certification or
production assurance is implied.

## References

- [ISO/IEC 27001 overview](https://www.iso.org/standard/27001)
- [ISO committee guidance on the Statement of Applicability](https://committee.iso.org/files/live/sites/jtc1sc27/files/resources/ISO-IECJTC1-SC27-WG1_N3298_Auditing%20Practices%20Note%20-%20SoA.pdf)
- [ISO committee discussion of Annex A controls](https://committee.iso.org/files/live/sites/jtc1sc27/files/resources/Journal%202025.pdf)
