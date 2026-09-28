# Project scope and repository fit

## Recommendation

Build a **fictional company operations and incident-response capstone**. The
portfolio outcome is a running environment plus a reproducible case study:
onboard an employee, apply policy, operate an internal service, observe a
benign security event, investigate it across systems, remediate, and verify
recovery. This is a systems-integration project rather than another detection
engine or SIEM dashboard.

## Review of existing work

| Existing repository | What it already proves | How this capstone uses it |
| --- | --- | --- |
| [SIEM detection engineering](https://github.com/jfrance167/siem-detection-engineering-lab) | Offline multi-source correlation over normalized JSONL | Run unchanged against sanitized exports from these VMs; compare results with live monitoring. |
| [SIEM logging pipeline](https://github.com/jfrance167/siem-logging-pipeline) | Synthetic event shipping, Loki, and Grafana | Keep as a separate transport demonstration. Do not deploy a duplicate Grafana stack here. |
| [Active Directory attack detection](https://github.com/jfrance167/active-directory-attack-detection-lab) | Offline correlation of normalized domain events | Use its event definitions and reporting format for a sanitized `DC01` export; do not rebuild the detector. |
| [Windows event investigation](https://github.com/jfrance167/windows-event-log-investigation) and [failed-login detector](https://github.com/jfrance167/failed-login-detector) | Windows collection and authentication analysis | Use authorized exports from `DC01` and `WS01`, then redact before any portfolio publication. |
| [Firewall hardening](https://github.com/jfrance167/firewall-hardening-lab) | Host firewall baseline and rollback | Apply the method to `APP01`; pair it with measured OPNsense network rules. |
| [File integrity monitor](https://github.com/jfrance167/file-integrity-monitor) | File baseline and change evidence | Monitor a safe directory on `APP01` and report an intentional file change. |
| [Vulnerability management](https://github.com/jfrance167/vulnerability-management-lab) | Simulated prioritization and closure | Use a real lab asset inventory, package versions, patch plan, and verified closure, without publishing raw host details. |
| [Web access control](https://github.com/jfrance167/web-access-control-security-lab) | Offline authorization model | Use its RBAC ideas when adding a future internal app; do not expose a vulnerable service. |
| [Ransomware response](https://github.com/jfrance167/ransomware-incident-response-lab) and [network forensics](https://github.com/jfrance167/network-forensics-pcap-lab) | Synthetic incident analysis | Use their report structure in a harmless live exercise with actual logs and optional sanitized captures. |
| [Phishing triage](https://github.com/jfrance167/automated-phishing-triage-toolkit) | Email parsing and scoring | Optional scenario input; do not add a mail server merely to repeat this project. |
| [ISO 27001 policy](https://github.com/jfrance167/iso-27001-information-security-policy) | Governance template | Draft a lab-specific asset register, access policy, and evidence-handling procedure. |

## Distinct capstone deliverables

1. **Company design:** topology, IP plan, asset owners, data-flow diagram,
   service dependencies, and a change log.
2. **Identity and endpoint operations:** `corp.example.test`, OUs, standard
   user, workstation join, baseline GPO, join and offboard procedure.
3. **Service operations:** internal service desk on `APP01`, health check,
   package inventory, backup and restore test, documented patch window.
4. **Network control:** default-deny inter-segment design, measured allow
   rules, firewall logs, and a before/after reachability matrix.
5. **Security operations:** Wazuh as the live collector, sanitized exports to
   existing Python projects, one cross-system incident timeline, and a closure
   report with evidence.

## Boundaries

- Wazuh is a log collection and visibility component, not the project thesis.
- The completed `siem-logging-pipeline` already proves live transport and
  visualization with synthetic events. Wazuh is optional supporting
  infrastructure here; a dashboard or detector is not a capstone deliverable.
- No new detector, phishing scorer, ransomware engine, or Grafana clone is
  planned.
- Only fictional identities and the isolated VM networks are used.
- Raw logs, VM disks, passwords, and installer output stay outside Git.
- The current broad server and management egress rules support installation;
  narrow them before claiming the network-control deliverable complete.
