# Public GitHub security review

Reviewed 2026-09-29 UTC for the fictional, isolated five-VM lab. The review
covers tracked source and configuration examples, Git history, the six selected
screenshots, and observed live tests. Guest disks, credentials, full firewall
configuration, and raw logs remain outside Git.

| File / location | Issue and exact value of concern | Severity | Recommended fix / result |
| --- | --- | --- | --- |
| `scripts/Configure-Firewall.php` | The installation helper's `--enable-temporary-egress` mode can create broad server and management passes. | Medium | The live broad passes were disabled by the scoped allowlist. The helper now refuses to run when `LAB-ALLOW ` rules already exist. Keep the mode limited to a fresh, isolated build. |
| `configs/wazuh-firewall-syslog.xml`, `scripts/Configure-FirewallSyslog.php` | Firewall events use `protocol` `udp` and `transport` `udp4` on port `514`; this does not encrypt or authenticate logs. | Medium | Bound Wazuh to `10.77.30.10`, allowed only `10.77.30.1`, and filtered OPNsense to `filterlog`. Documented the residual lab risk in `SECURITY.md` and `FIREWALL_POLICY.md`. Replace with authenticated TLS before real data or production use. |
| `README.md`, `FIREWALL_POLICY.md` | The fictional service desk uses TCP `80` and management certificates are self-signed. | Medium | Kept the service on isolated internal networks and disclosed the limit. Add HTTPS and trusted certificates before any real-data reuse. |
| `FIREWALL_POLICY.md` F01 / F05 | Source `10.77.10.0/24`, dynamic RPC `49152–65535` to the DC, and server/SIEM public TCP `443` are broader than a final enterprise policy. | Medium | Restricted destinations and ports, tested sign-in and policy update, and documented DHCP reservation, RPC refinement, and patch-window review as open scope decisions. |
| `ISO27001_CONTROL_MAPPING.md` 8.8, 8.15 | Ubuntu reports pending security updates; Windows configuration assessment alerts include scores below 30/100. The SIEM previously had VirtualBox disk write errors. | Medium | Recorded these as open hardening and operational risks. Fresh events and active services were verified after the host restart, with zero matching guest kernel I/O errors in the current boot. Patch and observe storage over time; do not claim production assurance. |
| `SECURITY.md`, `README.md` (previous text) | Earlier text said broad passes and Windows ingestion were still pending after both had been verified. | Low | Updated status to match the live allowlist, three active agents, Windows logon alerts, Linux alerts, and firewall rule `100100`. |
| `evidence/` | Raw console images can disclose identities, management details, or secrets. | Low | Only six reviewed PNGs are allowlisted. Each was visually checked for credentials and real identifiers; PNG text, EXIF, and compressed text chunks were absent. All other console captures are ignored. |
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
  fresh safe events, including a firewall deny rule match.
- [x] Keep credentials, guest disks, installation media, full configs, raw
  logs, captures, and unreviewed screenshots out of Git.
- [x] Mark HTTP, UDP Syslog, self-signed certificates, patching, benchmark
  scores, and storage observation as open lab risks.
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
