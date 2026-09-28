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
| Lateral movement from a user endpoint | Segment users, servers, and management; allow documented services; deny and log other routed flows. | Positive domain/app/agent tests and negative port tests pass after replacing broad rules. |
| Exposure of credentials or private telemetry | Keep private configs and logs outside Git, scan public history, review screenshots. | Public tree and alert queues checked before release. |
| Missing or altered security events | Verify source enrollment, event arrival, time synchronization, retention, and protected access. | Timestamped Windows, Linux, and firewall samples and source health recorded privately. Wazuh currently lists only its local manager. |
| Insecure lab-only services | Isolate HTTP and self-signed management endpoints; schedule TLS/auth improvement. | Risk remains open until TLS and access restrictions are tested. |
| Unapplied operating-system security updates | Inventory pending updates, patch during a maintenance window, and verify service recovery. | `APP01` currently reports 50 standard security updates pending; record patch result and exceptions privately. |

## Selected controls and evidence status

| ISO/IEC 27001:2022 Annex A control | Why selected | Current evidence | Status / next test |
| --- | --- | --- | --- |
| 5.9 Inventory of information and other associated assets | Identify systems and owners before setting rules. | Five-VM inventory and address plan in `README.md`. | **Partial:** record OS versions, owner, data class, and review date. |
| 5.15 Access control | Limit access to domain, network services, and management. | Synthetic standard account and domain join documented. | **Partial:** test role restrictions and management access. |
| 8.8 Management of technical vulnerabilities | Identify and remediate exposed packages. | `APP01` reports pending updates at console login. | **Open:** patch, reboot if required, and verify service and event collection. |
| 8.15 Logging | Preserve useful security event records. | Wazuh services active; user reports ingestion; live agent list shows only local manager `ID 000`. | **Partial:** enroll and verify Windows/Linux sources, configure firewall forwarding, record timestamps, retention, and log protection. |
| 8.16 Monitoring activities | Review events and respond to anomalies. | Wazuh is installed. | **Pending:** show one safe event, triage, and closure. |
| 8.20 Networks security | Control and observe traffic between networks. | OPNsense filtering enabled; rule design in `FIREWALL_POLICY.md`. | **Open:** remove broad live rules, test allows and logged denies. |
| 8.21 Security of network services | Define security needs for DNS, AD, web, telemetry, and update access. | Service inventory and candidate port matrix in `FIREWALL_POLICY.md`. | **Partial:** confirm live ports, encryption, authentication, and ownership. |
| 8.22 Segregation of networks | Keep users, servers, and management in separate zones. | Three VirtualBox internal networks with OPNsense routing. | **Partial:** verify default deny; add host firewall controls for same-subnet traffic. |
| 8.32 Change management | Make changes reviewable and reversible. | Dated configuration backup and test/rollback steps in firewall policy. | **Partial:** attach a private change record and completed test results. |

Status is evidence based: **open** means a known risk remains; **pending**
means no adequate test is recorded; **partial** means one part is shown but the
control is not fully demonstrated. A claim that the lab "follows ISO 27001"
should link to this mapping and disclose these statuses. No certification or
production assurance is implied.

## References

- [ISO/IEC 27001 overview](https://www.iso.org/standard/27001)
- [ISO committee guidance on the Statement of Applicability](https://committee.iso.org/files/live/sites/jtc1sc27/files/resources/ISO-IECJTC1-SC27-WG1_N3298_Auditing%20Practices%20Note%20-%20SoA.pdf)
- [ISO committee discussion of Annex A controls](https://committee.iso.org/files/live/sites/jtc1sc27/files/resources/Journal%202025.pdf)
