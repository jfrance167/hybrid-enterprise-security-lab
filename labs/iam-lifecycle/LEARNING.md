# Learning and review

- Fresh ordinary-user logon processes and actual read/write attempts exposed access that group listings alone would miss. Share and NTFS permissions both mattered: the direct Review grant used NTFS Modify plus SMB Change.
- Disabled accounts can retain directory entitlements. The planted ops2 finding therefore required both entitlement removal and separate online authentication checks.
- A closed SMB stream can throw again during Dispose. The first report preserved observed stream failure but lacked a fresh read. Recording the cleanup code and continuing the independent read allowed the retest to distinguish access denial from unrelated network failure.
- PowerShell's comma/addition precedence concatenated two private paths in the initial client helper. Read-only diagnosis showed the files existed and were protected. Explicit Join-Path parentheses fixed the expression; the full joiner probe passed afterward.
- New-Object flattened two LDAP search attributes into a single attribute name. An explicit typed SearchRequest constructor fixed the healthy RootDSE control. LDAP49 alone did not provide the disabled-account reason, so NETWORK logon error1331 supplied a separate numeric check.
- PowerShell7.5 automatically parsed ISO JSON dates. Passing those dates through string formatting lost fractional seconds in the first artifact verifier. Direct DateTimeOffset conversion preserved the recorded timing precision; the regression asserts all three exact metrics.
- Snapshot creation is not proof of restoration. This exercise demonstrated a narrow inverse membership recovery; snapshot restoration remains untested.

## ECC implementing-agent review

Review covered the setup/provisioning guards, private ACLs, user-process isolation, stage prerequisites, exact resource baselines, exception classification, bounded readiness, retained-session cleanup, online healthy controls, final state and the read-only artifact verifier. Source, callers and actual failure evidence were inspected. Corrections above were retested. The one-use retest preparation requires exact ownership and original ACL equality; the resulting account was verified disabled and role-free.

The artifact verifier passed the baseline and all twelve negative cases. It parsed all supplied PowerShell sources without errors locally. Repository CI also parses sources, runs PSScriptAnalyzer error checks and retains the existing secret scan and CodeQL Actions review. Actual CI results belong to the pull request; a configured workflow alone is not a passed scan. Bandit does not apply because this extension adds no Python source. CodeQL has no PowerShell or PHP analysis language; the existing Actions-language scan is retained.

No unresolved actionable findings were identified in the final focused self-review. This is not an independent security audit or production-readiness assessment. Artifact hashes detect changes but cannot prove the tests were run. VM tests, numeric failures and observed source references are the evidence for the described lab behavior.
