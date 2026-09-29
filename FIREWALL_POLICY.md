# Lab firewall policy and verification

This is the implemented allowlist and test record for the fictional, isolated
VirtualBox lab. The source interface is where OPNsense evaluates a new
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

## Allowlist and remaining scope decisions

The named rules are active on OPNsense. The matrix includes some AD ports
that have not each been exercised; remove any unused ports after a full
domain logon and policy test. Domain logon and `gpupdate /force` succeeded.
`WS01` uses DHCP (`10.77.10.139` during the
test), so the users-subnet source is broader than one reserved host.

| ID | Source | Destination | Protocol / destination port | Business reason | Verification |
| --- | --- | --- | --- | --- | --- |
| F01 | `WS01` | `DC01` | TCP/UDP 53, 88, 389, 464; TCP 135, 445, 3268, 49152–65535; UDP 123 | AD DNS, authentication, policy, and time. Dynamic RPC is limited to the DC destination. | Domain sign-in, DNS SRV query, `gpupdate`, firewall hit counts |
| F02 | `WS01` | `APP01` | TCP 80 | Fictional service desk until HTTPS is configured | HTTP 200; TCP 22 denied and logged |
| F03 | Enrolled `WS01`, `DC01`, `APP01` only | `SIEM01` | TCP 1514; TCP 1515 closed after enrollment | Wazuh agent traffic | All three agents active; manager alerts from each source |
| F04 | `LAB-FW` only | `SIEM01` | UDP 514 on the isolated management network | Firewall deny events | Filterlog-only forwarding generated Wazuh rule `100100` for denied `10.77.10.139` to `10.77.30.10:443` at 02:43 UTC |
| F05 | Servers and SIEM | Public endpoints outside `10.77.0.0/16` via NAT | TCP 443; DNS to the segment gateway | OS and package maintenance; review or disable outside patch windows | DC DNS forwarder and external lookup verified; package updates and workstation access still need review |

No general users-to-management access is approved. Wazuh dashboard/API,
OPNsense management, SSH, RDP, and SMB administration require an explicit
source host, named operator, and separate change record. Wazuh's default
agent ports are documented by its publisher; its Syslog listener is disabled
by default, so F04 cannot be enabled solely from this table.

Live `SIEM01` inspection found TCP 1514/1515 for Wazuh agents and TCP 443
(dashboard) and 55000 (API) bound to all guest interfaces. The firewall now
denies users-to-management access except TCP 1514, despite the dashboard/API
listeners. UDP 514 is bound only to `10.77.30.10` and accepts only
`10.77.30.1` in Wazuh's remote syslog configuration.

`APP01` uses `10.77.20.1` for DNS and its default gateway. The allowlist also
permits `DC01` to query that gateway as a DNS forwarder. `DC01` uses
`10.77.20.1` as its forwarder, and an external-name A lookup through the DC
DNS service succeeded after the rule update.

Microsoft lists additional AD ports for some functions, including dynamic
RPC. F01 deliberately scopes that range to `DC01`, but should be narrowed
further if a fixed RPC port is configured and tested. `APP01` and `DC01` share
one subnet, so their direct traffic does not traverse OPNsense; host firewalls
must cover traffic within that segment.

## Change and acceptance record

1. Export a dated OPNsense configuration backup and record the current rule
   order, DHCP reservation, and firewall log settings. Keep the backup private.
2. Put the specific allows above any broader rules. The reviewed script
   creates a private backup and disables the four temporary broad passes.
   Preserve console access for rollback.
3. Verify F01–F03 after the change. Exercise a denied users-to-management
   dashboard/API connection and a denied unrelated users-to-servers port.
   Record the source, destination, port, timestamp, and matching deny rule.
4. Check the Wazuh source list and test events. F04 currently uses plain UDP
   Syslog; the isolated VirtualBox management network, destination binding,
   and `allowed-ips` setting limit exposure but do not authenticate or encrypt
   the packet. Add authenticated TLS forwarding before any production reuse.
5. Sanitize screenshots and exports before committing. Keep full firewall
   configs, raw logs, credentials, and host identifiers outside Git.
6. Recheck rule hit counts and the deny log after a reboot. Record the owner,
   date, test result, and rollback outcome in a change record.

## Current status

On 2026-09-29, `configctl filter reload` returned `OK` after the backed-up
change. `pfctl -sr` showed named source/destination/port rules and zero
`pass in ... to any` rules on internal `em1`, `em2`, and `em3`. The workstation
received HTTP 200 from `APP01`, resolved the AD SRV record through `DC01`,
and connected to Wazuh on TCP 1514. Domain sign-in and `gpupdate /force`
succeeded for the workstation. TCP 443 to the Wazuh dashboard returned
`False`; OPNsense recorded `block,in` and the manager generated rule `100100`
with parsed source `10.77.10.139`, destination `10.77.30.10`, and destination
port `443`. TCP 22 from `WS01` to `APP01` also failed; OPNsense recorded a
`block,in` packet for `10.77.10.139` to `10.77.20.20:22` at 02:55 UTC.
`APP01`, `DC01`, and `WS01` were active Wazuh agents with alerts, including
an `APP01` SSH event (`5710`).

The rule matrix is implemented, but DHCP reservation, every AD port test,
Windows workstation update access, and authenticated Syslog transport remain
open refinements. The SIEM previously had VirtualBox write errors; recovery
and fresh event arrival were observed after direct VT-x boot, while longer
disk-health monitoring remains open.

## Vendor references

- [OPNsense rule order, state, and logging](https://docs.opnsense.org/manual/firewall.html)
- [Microsoft AD firewall requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [Wazuh architecture and required ports](https://documentation.wazuh.com/current/getting-started/architecture.html)
