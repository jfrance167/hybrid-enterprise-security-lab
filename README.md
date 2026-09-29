# Northstar Labs: enterprise operations and incident response capstone

This fictional, isolated company network practices identity, endpoints,
applications, network policy, operations, evidence handling, and incident
response. It connects existing focused GitHub projects to live systems without
rebuilding their detectors or Grafana pipeline. No real users, production
credentials, or physical-LAN access are involved. See
[PROJECT_SCOPE.md](PROJECT_SCOPE.md).

The [authorized deny triage exercise](INCIDENT_EXERCISE.md) connects identity,
application access, firewall policy, Wazuh ingestion, and analyst disposition.

**Educational lab only.** This configuration is not production ready. It uses
evaluation operating systems and self-signed management certificates. The
internal application uses HTTPS with a private lab CA trusted on `WS01`;
OPNsense filterlog uses the enrolled Wazuh agent. Use only
fictional data on the isolated VirtualBox networks. See [SECURITY.md](SECURITY.md),
the [firewall rule and test plan](FIREWALL_POLICY.md), and the
[ISO/IEC 27001:2022 lab control mapping](ISO27001_CONTROL_MAPPING.md).

## First-build topology

```text
                         VirtualBox NAT (outbound only)
                                    |
                              LAB-FW (OPNsense)
                    ________________|________________
                   |                |                |
            LAB-USERS          LAB-SERVERS       LAB-MGMT
          10.77.10.0/24       10.77.20.0/24   10.77.30.0/24
             LAB-WS01       LAB-DC01, LAB-APP01  LAB-SIEM01
```

Only `LAB-FW` has a NAT adapter. All other adapters use VirtualBox internal
networks. There are no bridged adapters, port forwards, or host-only interfaces.
Administration starts through VM consoles. The internal firewall interfaces
use the named allowlist in [`FIREWALL_POLICY.md`](FIREWALL_POLICY.md); the four
temporary broad passes were disabled after installation.

| VM | OS | RAM | CPUs | Dynamic disk | NICs |
| --- | --- | ---: | ---: | ---: | --- |
| LAB-FW | OPNsense | 4 GB | 2 | 16 GB | NAT, users, servers, management |
| LAB-DC01 | Windows Server 2025 evaluation | 4 GB | 2 | 50 GB | servers |
| LAB-WS01 | Windows 11 Enterprise evaluation | 4 GB | 2 | 64 GB | users |
| LAB-APP01 | Ubuntu Server 24.04 LTS | 2 GB | 2 | 24 GB | servers |
| LAB-SIEM01 | Ubuntu Server 24.04 LTS + Wazuh | 8 GB | 2 | 60 GB | management |

The five VMs reserve **22 GB of guest RAM total** when all run, below the
32 GB cap. Dynamic disk sizes are maximum capacities, not immediate usage.
The VM builder requires at least 100 GB free before creation; monitor free
space afterward as operating systems and updates grow.

## Address plan

| Network | Gateway | Static guests |
| --- | --- | --- |
| users `10.77.10.0/24` | `10.77.10.1` | `LAB-WS01`: reserved DHCP `.139` |
| servers `10.77.20.0/24` | `10.77.20.1` | `LAB-DC01`: `.10`, `LAB-APP01`: `.20` |
| management `10.77.30.0/24` | `10.77.30.1` | `LAB-SIEM01`: `.10` |

The fictional AD DNS name is `corp.example.test`. `LAB-DC01` supplies domain
DNS; OPNsense supplies user-network DHCP. The workstation uses domain DNS.

## Build order

1. Create VMs and empty dynamic disks with `scripts/New-LabVMs.ps1`.
2. Mount official installation media and install the firewall.
3. Configure firewall interfaces and the three isolated networks.
4. Install `LAB-DC01`; configure AD DS, DNS, and the fictional domain.
5. Install and domain-join `LAB-WS01`.
6. Install `LAB-APP01` and one harmless internal web service.
7. Install `LAB-SIEM01` and onboard Windows, Linux, and firewall logs.

## Build status (2026-09-29)

- Five VMs installed with **22 GB** assigned guest RAM in total. VMs may be
  paused or powered off during maintenance.
- OPNsense installed with users, servers, and management segments. The four
  temporary broad passes are disabled; 23 named IPv4 allows are defined for
  AD, the internal app, Wazuh telemetry, and DNS. Public TCP 443 update
  egress requires the explicit `--maintenance-egress` option and is currently
  disabled. The workstation address is reserved to its private VM MAC and is
  the source of the user-network allows. Post-change tests returned HTTPS 200
  from the app with certificate validation, an AD DNS SRV answer,
  TCP 1514 success to Wazuh, and TCP 443 failure to its dashboard. OPNsense
  logged the denied `WS01` to `SIEM01:443` packet. `WS01` to `APP01:22`
  also failed and appeared as a firewall deny. Domain `gpupdate /force`
  succeeded, and the DC DNS forwarder resolved an external name.
- Windows Server 2025 provides `corp.example.test` AD DS and DNS. Lab OUs and
  the synthetic `analyst1` / `SOC-Analysts` account exist.
- Windows 11 Enterprise joined the domain as `WS01`; domain DNS SRV lookup was
  verified before the join. The synthetic `CORP\analyst1` account signed in.
- Ubuntu `APP01` runs Nginx on `10.77.20.20:443` only and serves the fictional
  internal service desk. Its key and lab CA key remain outside Git.
- From the domain user's workstation, the internal service desk returned
  HTTPS `200 OK` at `10.77.20.20`; TCP 80 was closed.
- Ubuntu `SIEM01` has Wazuh 4.14.8 installed. `APP01` (`ID 001`), `DC01`
  (`ID 002`), `WS01` (`ID 003`), and the OPNsense `LAB-FW` agent (`ID 004`)
  were active at the manager. The manager
  recorded an `APP01` sudo alert (`5402`), `DC01` Windows logon alerts
  (`60106`/`60118`), `WS01` Windows configuration assessment alerts, and an
  OPNsense users-to-SIEM deny alert (`100100`). After replacing isolated UDP
  syslog with the authenticated Wazuh agent, a new application-to-SIEM deny
  produced rule `100101` under agent `004`; UDP 514 was removed. A harmless failed local SSH
  login on `APP01` produced Wazuh rule `5710`, and a `WS01` domain logon
  produced rule `60106`. The Windows agent installers
  matched publisher SHA-512 files and had valid Wazuh signatures.
- VirtualBox previously reported two failed writes to the SIEM virtual disk.
  An offline read-only ext4 check found no structural errors. After the user
  authorized disabling the host Hyper-V compatibility path and restarting,
  VirtualBox used VT-x directly and Wazuh booted with active services and
  fresh events. Manager, indexer, and dashboard were active at the latest
  check, with no guest kernel I/O error matches in the current boot. This is
  a recovery observation, not long-term disk assurance.

Those domain, application, firewall-deny, and event-ingestion prerequisites
were verified before the authorized exercise in `INCIDENT_EXERCISE.md`.

## Acceptance evidence

- A domain user signs into `LAB-WS01` (verified).
- `LAB-WS01` resolves the domain and reaches the internal HTTPS application
  (verified). Unapproved `APP01:22` and `SIEM01:443` connections were denied
  and logged by OPNsense (verified).
- A denied workstation-to-SIEM dashboard connection appeared in the OPNsense
  filter log and as Wazuh rule `100100` (verified on the earlier isolated UDP
  feed); a fresh application-to-SIEM deny produced `100101` on the agent feed.
- A Linux `APP01` sudo event, a `DC01` Windows logon, `WS01` Windows
  assessment/logon events, a Linux SSH event, and the firewall deny arrived
  at `LAB-SIEM01` (verified). Longer storage observation remains open.
- Four reviewed screenshots are selected in [`evidence/`](evidence/README.md)
  as candidate portfolio evidence, including the validated firewall rule and
  event-ingestion views. Other console screenshots are
  excluded from Git; no passwords, keys, or full private logs belong in Git.
  Credentials are stored outside this project under a private VM directory.

## Media

Download installation media from the publishers, and verify checksums where
published. Windows Server and Windows 11 Enterprise evaluations expire, so
record install dates and plan for rebuilds or licensed media. The VM creation
script does not download media, install an operating system, or start VMs.

- [OPNsense](https://opnsense.org/download/)
- [Windows Server 2025 evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025)
- [Windows 11 Enterprise evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)
- [Ubuntu Server](https://ubuntu.com/download/server)

## License

Project source and documentation use the [MIT License](LICENSE). Operating
systems, Wazuh, OPNsense, and VirtualBox remain under their own licenses and
are not redistributed here.
