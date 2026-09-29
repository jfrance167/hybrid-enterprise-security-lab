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
`WS01` has a Dnsmasq DHCP reservation for `10.77.10.139`, tied to its private
VM MAC. The user-network rules use that one address.
This is address scoping, not device authentication; another guest on the
same users segment could spoof the reserved IP/MAC.

| ID | Source | Destination | Protocol / destination port | Business reason | Verification |
| --- | --- | --- | --- | --- | --- |
| F01 | `WS01` | `DC01` | TCP/UDP 53, 88, 389, 464; TCP 135, 445, 3268, 49152–65535; UDP 123 | AD DNS, authentication, policy, and time. Dynamic RPC is limited to the DC destination. | Domain sign-in, DNS SRV query, `gpupdate`, firewall hit counts |
| F02 | `WS01` at `.139` | `APP01` | TCP 443 | Fictional HTTPS service desk | Certificate-validated HTTPS 200; TCP 80 and 22 denied |
| F03 | Enrolled `WS01`, `DC01`, `APP01` only | `SIEM01` | TCP 1514 | Wazuh agent traffic | All three endpoint agents active; manager alerts from each source |
| F04 | `LAB-FW` on the management segment | `SIEM01` | TCP 1514 | Authenticated Wazuh agent carrying `filterlog` | Agent `004` active; fresh blocked `APP01` to `SIEM01:443` produced rule `100101` |
| F05 | `DC01`, `APP01`, and `SIEM01`, only during maintenance | Public endpoints outside `10.77.0.0/16` via NAT | TCP 443 | OS and package updates | Disabled in the normal 23-rule policy; explicitly enable `--maintenance-egress` for a recorded patch window and disable afterward |

No general users-to-management access is approved. Wazuh dashboard/API,
OPNsense management, SSH, RDP, and SMB administration require an explicit
source host, named operator, and separate change record. Wazuh's default
agent ports are documented by its publisher. The previous cleartext UDP 514
target and Wazuh listener were removed after agent-based ingestion was tested.

Live `SIEM01` inspection found TCP 1514/1515 for Wazuh agents and TCP 443
(dashboard) and 55000 (API) bound to all guest interfaces. The firewall now
denies users-to-management access except TCP 1514, despite the dashboard/API
listeners. There is no UDP 514 Wazuh listener after the cutover.

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
4. Check the Wazuh source list and test events. The official OPNsense
   `os-wazuh-agent` plugin forwards only `filterlog` over the authenticated
   Wazuh agent channel. Confirm a fresh deny alert has agent `004` / `LAB-FW`.
   For migration from the old feed, run `Disable-FirewallSyslog.php --apply`
   at `LAB-FW`, then remove the separate legacy `<ossec_config>` block
   containing `<connection>syslog</connection>` and `<port>514</port>` from
   `/var/ossec/etc/ossec.conf` on `SIEM01` after making a private backup.
   Restart `wazuh-manager`, verify UDP 514 has no listener, and repeat the
   fresh deny test. The firewall script changes only the OPNsense sender.
5. Sanitize screenshots and exports before committing. Keep full firewall
   configs, raw logs, credentials, and host identifiers outside Git.
6. Recheck rule hit counts and the deny log after a reboot. Record the owner,
   date, test result, and rollback outcome in a change record.

## Current status

On 2026-09-29, `configctl filter reload` returned `OK` after the backed-up
change. `pfctl -sr` showed named source/destination/port rules and zero
`pass in ... to any` rules on internal `em1`, `em2`, and `em3`. The workstation
received certificate-validated HTTPS 200 from `APP01`, resolved the AD SRV record through `DC01`,
and connected to Wazuh on TCP 1514. Domain sign-in and `gpupdate /force`
succeeded for the workstation. TCP 443 to the Wazuh dashboard returned
`False`; OPNsense recorded `block,in` and the manager generated rule `100100`
with parsed source `10.77.10.139`, destination `10.77.30.10`, and destination
port `443`. TCP 22 from `WS01` to `APP01` also failed; OPNsense recorded a
`block,in` packet for `10.77.10.139` to `10.77.20.20:22` at 02:55 UTC.
`APP01`, `DC01`, `WS01`, and `LAB-FW` were active Wazuh agents. The original
`100100` test used the earlier isolated UDP feed; after the cutover, a fresh
blocked `APP01` to `SIEM01:443` event produced `100101` as agent `004`.
Wazuh TCP 1514 stayed active; UDP 514 had no listener. An `APP01` SSH event
(`5710`) also arrived.

The rule matrix is implemented. Every AD port test, Windows workstation update
access, and the maintenance patch cycle remain open. The broad AD dynamic RPC
range is limited to `WS01` and `DC01`, but awaits a fixed-port configuration
and regression test. The SIEM previously had VirtualBox write errors; recovery
and fresh event arrival were observed after direct VT-x boot, while longer
disk-health monitoring remains open.

## Vendor references

- [OPNsense rule order, state, and logging](https://docs.opnsense.org/manual/firewall.html)
- [Microsoft AD firewall requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [Wazuh architecture and required ports](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [OPNsense Wazuh agent plugin](https://docs.opnsense.org/manual/wazuh-agent.html)
