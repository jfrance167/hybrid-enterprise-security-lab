# Lab firewall policy and verification

This is the approved-flow design for the fictional, isolated VirtualBox lab.
Rule status must be checked against the running OPNsense configuration before
claiming enforcement. The source interface is where OPNsense evaluates a new
connection; replies use the resulting state. The default policy for traffic
between segments is deny, with denied attempts logged.

## Assets and rule owner

| Segment | Network | Assets | Purpose |
| --- | --- | --- | --- |
| Users | `10.77.10.0/24` | `WS01` | Standard employee workstation |
| Servers | `10.77.20.0/24` | `DC01` (`.10`), `APP01` (`.20`) | Identity, DNS, internal service |
| Management | `10.77.30.0/24` | `SIEM01` (`.10`) | Security telemetry |

The lab operator owns and reviews these rules after each service change.
The only WAN connection is OPNsense's VirtualBox NAT adapter. No VM has a
bridged interface or a port forward.

## Proposed allowlist

These are candidate requirements, not proof that every port is in use. Confirm
each flow in the firewall log and remove unused ports after a successful
domain logon, application request, and event-ingestion test. The `WS01` address
should be reserved in DHCP before rules target the host; until then a rule
using the users subnet must be called out as broader scope.

| ID | Source | Destination | Protocol / destination port | Business reason | Verification |
| --- | --- | --- | --- | --- | --- |
| F01 | `WS01` | `DC01` | TCP/UDP 53, 88, 389, 464; TCP 135, 445, 3268, 49152–65535; UDP 123 | AD DNS, authentication, policy, and time. Dynamic RPC is limited to the DC destination. | Domain sign-in, DNS SRV query, `gpupdate`, firewall hit counts |
| F02 | `WS01` | `APP01` | TCP 80 | Fictional service desk until HTTPS is configured | HTTP 200 and an unrelated port denied |
| F03 | Enrolled `WS01`, `DC01`, `APP01` only | `SIEM01` | TCP 1514; TCP 1515 only during enrollment | Wazuh agent traffic | Agent status and a timestamped test event at the manager |
| F04 | `LAB-FW` only | `SIEM01` | Syslog listener port and protocol **only after confirmed** | Firewall deny events | Deny log observed at the manager with matching time and rule |
| F05 | Each VM requiring updates | Public update endpoints via NAT | TCP 443; DNS and time only to named resolvers | OS and package maintenance | Record endpoint, time, and rule hits; disable outside patch window if practical |

No general users-to-management access is approved. Wazuh dashboard/API,
OPNsense management, SSH, RDP, and SMB administration require an explicit
source host, named operator, and separate change record. Wazuh's default
agent ports are documented by its publisher; its Syslog listener is disabled
by default, so F04 cannot be enabled solely from this table.

Live `SIEM01` inspection found TCP 1514 and 1515 listening for Wazuh agents,
and TCP 443 (dashboard) and 55000 (API) bound to all guest interfaces. No
Syslog port 514 listener was found. The current users-to-any pass rule can
therefore reach management services across segments; replacing that rule is
urgent. Do not allow 443 or 55000 from the user subnet merely because the
service is listening.

`APP01` currently uses `10.77.20.1` for DNS and its default gateway, so its
DNS rule can target only that firewall address. The other guests' resolver
settings must be inspected before their update/DNS rules are finalized.

Microsoft lists additional AD ports for some functions, including dynamic
RPC. F01 deliberately scopes that range to `DC01`, but should be narrowed
further if a fixed RPC port is configured and tested. `APP01` and `DC01` share
one subnet, so their direct traffic does not traverse OPNsense; host firewalls
must cover traffic within that segment.

## Change and acceptance record

1. Export a dated OPNsense configuration backup and record the current rule
   order, DHCP reservation, and firewall log settings. Keep the backup private.
2. Put the specific allows above any broader rules. Remove the temporary
   server and management egress rules and replace the default users-to-any
   pass rule. Preserve console access for rollback.
3. Verify F01–F03 after the change. Exercise a denied users-to-management
   dashboard/API connection and a denied unrelated users-to-servers port.
   Record the source, destination, port, timestamp, and matching deny rule.
4. Check the Wazuh source list, test events, and whether F04 uses an encrypted
   transport. If plain Syslog is used, document the isolated-network risk and
   plan an authenticated/encrypted forwarder before any production reuse.
5. Sanitize screenshots and exports before committing. Keep full firewall
   configs, raw logs, credentials, and host identifiers outside Git.
6. Recheck rule hit counts and the deny log after a reboot. Record the owner,
   date, test result, and rollback outcome in a change record.

## Current status

As of 2026-09-28, live OPNsense inspection confirmed three broad IPv4 pass
rules: `Default allow LAN to any rule`, `Lab server subnet outbound`, and
`Lab management subnet outbound`. The default IPv6 LAN pass rule also remains.
The user reported verification of Wazuh event ingestion, but the live Wazuh
agent list contains only the local manager (`ID 000`) and no enrolled Windows
or Linux endpoints. Which event was observed still needs to be recorded. Do
not use the selected Wazuh service-status screenshot as evidence of ingestion.

## Vendor references

- [OPNsense rule order, state, and logging](https://docs.opnsense.org/manual/firewall.html)
- [Microsoft AD firewall requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [Wazuh architecture and required ports](https://documentation.wazuh.com/current/getting-started/architecture.html)
