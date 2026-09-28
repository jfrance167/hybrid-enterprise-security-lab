# Northstar Labs: enterprise operations and incident response capstone

This fictional, isolated company network practices identity, endpoints,
applications, network policy, operations, evidence handling, and incident
response. It connects existing focused GitHub projects to live systems without
rebuilding their detectors or Grafana pipeline. No real users, production
credentials, or physical-LAN access are involved. See
[PROJECT_SCOPE.md](PROJECT_SCOPE.md).

**Educational lab only.** This configuration is not production ready. It uses
evaluation operating systems, temporary broad outbound firewall rules, an
internal HTTP service, and self-signed management certificates. Use only
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
Administration starts through VM consoles. The firewall has explicit outbound
rules for the server and management subnets. These currently allow broad egress
for installation and should be narrowed after service dependencies are measured.

| VM | OS | RAM | CPUs | Dynamic disk | NICs |
| --- | --- | ---: | ---: | ---: | --- |
| LAB-FW | OPNsense | 4 GB | 2 | 16 GB | NAT, users, servers, management |
| LAB-DC01 | Windows Server 2025 evaluation | 4 GB | 2 | 50 GB | servers |
| LAB-WS01 | Windows 11 Enterprise evaluation | 4 GB | 2 | 64 GB | users |
| LAB-APP01 | Ubuntu Server 24.04 LTS | 2 GB | 2 | 24 GB | servers |
| LAB-SIEM01 | Ubuntu Server 24.04 LTS + Wazuh | 8 GB | 4 | 60 GB | management |

The five VMs reserve **22 GB of guest RAM total** when all run, below the
32 GB cap. Dynamic disk sizes are maximum capacities, not immediate usage.
The VM builder requires at least 100 GB free before creation; monitor free
space afterward as operating systems and updates grow.

## Address plan

| Network | Gateway | Static guests |
| --- | --- | --- |
| users `10.77.10.0/24` | `10.77.10.1` | `LAB-WS01`: DHCP `.100`–`.150` |
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

## Build status (2026-09-28)

- Five VMs installed and running at **22 GB** assigned guest RAM.
- OPNsense installed with users, servers, and management segments. Packet
  filtering is enabled; outbound server and management rules are logged.
- Windows Server 2025 provides `corp.example.test` AD DS and DNS. Lab OUs and
  the synthetic `analyst1` / `SOC-Analysts` account exist.
- Windows 11 Enterprise joined the domain as `WS01`; domain DNS SRV lookup was
  verified before the join. The synthetic `CORP\analyst1` account signed in.
- Ubuntu `APP01` runs Nginx and serves the fictional internal service desk.
- From the domain user's workstation, the internal service desk returned
  HTTP `200 OK` at `10.77.20.20`.
- Ubuntu `SIEM01` has Wazuh 4.14 installed; manager, indexer, and dashboard
  services report active. The lab operator reports verifying event ingestion.
  The observed source list, listener ports, and timestamped test event have
  not yet been recorded in this repository.

Do not start an incident exercise until ordinary domain logon, application
access, denied cross-segment traffic, and event ingestion are demonstrated.

## Acceptance evidence

- A domain user signs into `LAB-WS01` (verified).
- `LAB-WS01` resolves the domain and reaches the internal application
  (verified). Restricting reachability to approved ports is pending.
- A denied cross-segment connection appears in firewall logs (pending).
- A Windows logon, Linux SSH event, and firewall deny arrive at `LAB-SIEM01`
  (source-by-source evidence pending; ingestion reported by the lab operator).
- Four reviewed setup screenshots are selected in [`evidence/`](evidence/README.md)
  as candidate portfolio evidence. Network-rule and event evidence will be
  added after those controls are validated. Other console screenshots are
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
