# Public GitHub security review

Reviewed 2026-09-29 UTC for the fictional, isolated five-VM lab. The review
covers tracked source and configuration examples, Git history, the four selected
screenshots, and observed live tests. Guest disks, credentials, full firewall
configuration, and raw logs remain outside Git.

| File / location | Issue and exact value of concern | Severity | Recommended fix / result |
| --- | --- | --- | --- |
| `scripts/Configure-Firewall.php` | The installation helper's `--enable-temporary-egress` mode can create broad server and management passes. | Medium | The live broad passes were disabled by the scoped allowlist. The helper now refuses to run when `LAB-ALLOW ` rules already exist. Keep the mode limited to a fresh, isolated build. |
| Removed `configs/wazuh-firewall-syslog.xml` and `scripts/Configure-FirewallSyslog.php` | The previous firewall feed used `protocol` `udp`, `transport` `udp4`, port `514`, without authentication or encryption. | Medium | Installed the official OPNsense `os-wazuh-agent` plugin with `filterlog` only. Agent `004` produced a fresh rule `100101` alert after removing the UDP sender and listener. `scripts/Disable-FirewallSyslog.php` records the retirement. |
| `configs/nginx-app-https.conf` and former service on TCP `80` | The fictional service desk previously served cleartext HTTP. | Medium | Bound Nginx to `10.77.20.20:443` only, installed a private-keyed lab certificate, trusted its CA on `WS01`, and verified HTTPS 200 without bypassing validation; TCP 80 was closed. Keys remain outside Git. Management certificates remain self-signed. |
| `scripts/Apply-FirewallAllowlist.php` F01 / F05 | The former workstation source was `10.77.10.0/24`; public update TCP `443` was always allowed. AD dynamic RPC `49152:65535` remains broad. | Medium | Reserved `10.77.10.139` to the private workstation MAC and scoped all user rules to that address. This is not device authentication. Public update egress now requires `--maintenance-egress`, is scoped to the three named servers, and is disabled in the normal policy. Dynamic RPC remains limited to the workstation address and DC; fixed-port configuration and regression testing remain open. |
| `ISO27001_CONTROL_MAPPING.md` 8.8, 8.15 | Ubuntu reports pending security updates; Windows configuration assessment alerts include scores below 30/100. The SIEM previously had VirtualBox disk write errors. | Medium | Recorded these as open hardening and operational risks. Fresh events and active services were verified after the host restart, with zero matching guest kernel I/O errors in the current boot. Patch and observe storage over time; do not claim production assurance. |
| `SECURITY.md`, `README.md`, `FIREWALL_POLICY.md` (previous text) | Earlier text described HTTP, UDP Syslog, three agents, and the broad DHCP source after the live configuration changed. | Low | Updated the status to match HTTPS, agent-based firewall logging, four agents, and host-scoped rules. |
| `evidence/` | Raw console images can disclose identities, management details, or secrets. | Low | Removed three outdated or redundant images; only four reviewed PNGs are allowlisted. The new agent-cutover image shows only fictional lab identities and IPs. All other console captures are ignored. |
| `.gitignore` | VM media, private keys, environment files, raw logs, captures, databases, and archives must not enter a public repository. | Low | Explicit ignore rules cover those formats; the staged file list and history secret scan are publication gates. |

No literal password, API key, token, SSH private key, certificate private key,
real customer data, or real public IP was found in the reviewed public files.
The example AD name `corp.example.test`, private `10.77.0.0/16` addresses, and
synthetic account `CORP\analyst1` identify only this lab. No malware samples,
exploit payloads, `eval`/`exec`, or downloaded code execution appear in the
published scripts. Windows agent installers were verified against publisher
SHA-512 files and valid Wazuh Authenticode signatures before use. The
configuration examples contain no working credentials or default passwords.

## Must fix before commit

- [x] Remove the live temporary broad passes; verify approved flows and logged
  denials for `WS01` to `SIEM01:443` and `APP01:22`.
- [x] Prevent the temporary-egress helper from re-enabling broad passes after
  the allowlist is installed.
- [x] Verify Wazuh ingestion from `APP01`, `DC01`, `WS01`, and `LAB-FW` with
  fresh safe events, including rule `100101` under firewall agent `004` after
  retiring UDP 514.
- [x] Keep credentials, guest disks, installation media, full configs, raw
  logs, captures, and unreviewed screenshots out of Git.
- [x] Replace internal HTTP and UDP Syslog; mark remaining self-signed
  management certificates, patching, benchmark scores, AD dynamic RPC, and
  storage observation as open lab risks.
- [x] Pin Actions to immutable commits, use minimum permissions, and require
  the protected-branch `CI Gate` before merging.

The publication process additionally requires the pull request's PHP,
PowerShell, history secret scan, CodeQL, and `CI Gate` checks to pass. After
merge, inspect the default-branch runs and open alert queues.

## Suggested `.gitignore`

The repository's [`.gitignore`](.gitignore) is the recommended lab policy:
deny `evidence/*` by default and allowlist only reviewed images; exclude
`.env*` (except a nonsecret `.env.example`), `*.key`, `*.pem`, `*.pfx`,
`*.p12`, `*.pcap*`, `*.evtx`, `*.log`, `*.db`, `*.sqlite*`, dumps, VM images,
installation media, and archives. Check the staged file list as well, because
ignore rules do not remove files already tracked in Git.

## What cannot be established from the public files

The public repo cannot prove the absence of credentials inside private VMs or
previously uncommitted local files. A point-in-time review cannot establish
long-term log retention, backup recovery, continuous disk health, complete
patching, or ISO/IEC 27001 certification. The selected control mapping is a
lab-specific working excerpt with explicit open gaps. Third-party operating
systems and tools are installed from their publishers and are not redistributed.
PHP has syntax lint and manual review here, not a full language-specific SAST
engine. PowerShell has PSScriptAnalyzer; CodeQL covers the Actions workflow.

## Publication gate

The initial public `main` commit passed the repository's security workflow,
and its code-scanning and secret-scanning alert queues were empty when last
checked. An active repository ruleset requires a pull request and passing
`CI Gate` for `main`.
