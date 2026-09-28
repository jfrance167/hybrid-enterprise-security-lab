# Public GitHub pre-commit review

Reviewed on 2026-09-28. This review covers the current project source,
configuration, four selected screenshots, and the proposed public file list.
The VM disks, live guest configuration, private credentials, and raw Wazuh logs
are outside this repository and are not published.

| File / location | Issue | Severity | Fix / status |
| --- | --- | --- | --- |
| `README.md` (previous credential-directory path) | The example path contained the host's Windows profile name. | Low | Replaced it with a generic private-directory description. |
| `scripts/Configure-Firewall.php` (cloned LAN `pass` rule) | Running the script created broad server and management outbound rules. | Medium | Added an explicit `--enable-temporary-egress` gate and warning. The live temporary rules still require narrowing; this project does not claim the network-control milestone is finished. |
| `.gitignore` and `evidence/fw-enabled.png` | The raw firewall screenshot was eligible for Git and showed interface/certificate details. Other credential and capture formats lacked explicit ignore rules. | Low | Raw firewall screenshot remains local and ignored; expanded ignore rules for environment files, keys, captures, logs, databases, archives, and VM artifacts. |
| `README.md` and `scripts/New-LabVMs.ps1` | The README's free-space advice was lower than the builder's 100 GB creation check. | Low | Documentation now states the script's 100 GB threshold. |
| Repository root | No license or explicit production-use warning. | Low | Added MIT license and `SECURITY.md`; proprietary/third-party installation media are not included. |

## Must fix before commit

- [x] Exclude credentials, recovery answers, disks, media, logs, packet captures,
  archives, and the raw firewall console screenshot from the public file list.
- [x] Inspect every selected screenshot for visible secrets, real identities,
  public IPs, and metadata. Four selected PNGs show only fictional lab
  identities and isolated addresses; no PNG text/EXIF chunks were found.
- [x] Mark broad egress, HTTP, self-signed certificates, and incomplete SIEM
  ingestion as limitations. The firewall script requires explicit opt-in.
- [x] Keep the 22 GB total guest RAM below the user's 32 GB limit and preserve
  NAT/internal-network-only VM definitions.
- [x] Add pinned, minimally privileged GitHub Actions for PowerShell analysis,
  PHP syntax, history secret scanning, and CodeQL analysis of Actions workflows.
- [x] Add licensing and safe-use guidance.

## Remaining lab work

The live firewall's temporary broad rules remain in place for installation;
narrowing and denied-traffic verification are pending. Wazuh manager, indexer,
and dashboard services are active, but agent enrollment and event ingestion
are pending. Those are stated limitations, not evidence of completed controls.

The proposed `.gitignore` is the suggested publication policy for this lab.
PowerShell and PHP are not CodeQL-supported source languages; the workflow
uses PSScriptAnalyzer for PowerShell, PHP syntax linting, and CodeQL for the
GitHub Actions workflow. Review PHP with a language-specific SAST tool before
extending the firewall script beyond this small, isolated setup helper.

No prior Git history exists for this project directory before repository
initialization. After publication, CI and the GitHub code-scanning alert queue
must be checked on the default branch.
