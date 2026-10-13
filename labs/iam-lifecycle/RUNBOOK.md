# Lab execution and recovery

Use only an owned isolated replica of Northstar. The helpers are records of a specific tested run, not a general production IAM tool. Review source before execution. DC01 must be the PDC for `corp.example.test`; WS01 must be its domain member. Keep independent console administration available. The existing repository build and firewall documentation supplies the network prerequisites.

## Preparation

1. Verify AD/DNS, workstation secure channel, SMB connectivity, available storage, evaluation license validity and isolated adapters. Save a baseline and VM snapshots. Snapshot restore remains an untested recovery option for this evidence set.
2. Use a scoped transient input share (`IAM_Input`, read-only) and public-result share (`IAM_Evidence`). Do not map personal folders or private credential storage. Load reviewed scripts into local guest ISE files. Host text input proved unreliable; VirtualBox Soft Keyboard delivered guest scancodes.
3. On a fresh replica only, `scripts/s.ps1` creates the dedicated OU, six identities, two role groups and two new protected shares. It refuses existing identifiers and records partial state. It generates fixture credentials inside a protected guest directory. Never rerun setup against this completed fixture.
4. `scripts/p.ps1` provisions those fixture credentials directly into protected WS01 storage using the encrypted, administrator-only temporary SMB share. Supply the existing lab administrator credential interactively; never put it in arguments or evidence. `scripts/x.ps1` removes that owned provisioning share after successful client provisioning. Verify removal before user testing.
5. A new fixture generates a new RunId. Review and replace the embedded RunId in the run-specific helpers with the new manifest value. Retain all host/domain/OU/ownership checks. The supplied evidence and scripts reference run `96cb9aaf65ac4de698f7cf5af0e09ca8` and must not be passed off as a new execution.

DC helpers are `m.ps1` (phase controller) and `o.ps1` (directory proof). WS helpers are `c.ps1` (fresh user-process parent), `e.ps1` (file operations), `l.ps1` (retained leaver stream) and `n.ps1` (online authentication). Fixture secrets remain in protected `Private` directories on the guests; exported reports contain only public synthetic observations.

## Control and sequence

The controller reads `dc-control.json` from IAM_Input. Its safe inspection phase is `Audit`:

```json
{"RunId":"96cb9aaf65ac4de698f7cf5af0e09ca8","Phase":"Audit"}
```

The client reads `client-control.json`. Each subject receives a separate logon process, unique result directory and four actual file operations. Example for the mover after its transfer:

```json
{"RunId":"96cb9aaf65ac4de698f7cf5af0e09ca8","Stage":"mover","Subjects":[{"Name":"iam.mover","Role":"SystemsOperator"}]}
```

For the full passing stages use the complete subject set below; a one-user example does not satisfy the controller's six/five-user prerequisite.

| DC phase | WS stage and subjects | Required observation |
| --- | --- | --- |
| Audit / prepared fixture | joiner, six original roles | 24 passing operations |
| Move | mover, six users; mover becomes operator | 24 passing operations |
| SeedReview | seeded, five enabled users; omit ops2 | Deliberate sec2/mover excess causes normal comparison failure |
| Remediate | remediated, five enabled users | 20 passing operations |
| Mistake | mistake, ops1 only | Ops read/write denied; normal comparison fails |
| Restore | recovered, five enabled users | 20 passing operations within 300 seconds of Mistake start |
| Offboard | leaver-session, leaver operator only | Start WS probe first, observe READY, run DC phase within 120 seconds |
| Audit / o.ps1 | final, sec1/sec2/ops1/mover | 16 passing operations; ops2/leaver disabled without roles |

sec1/sec2 are readers throughout. ops1/leaver are operators throughout their enabled stages. ops2 is an operator through mover. The controller refuses an already attempted phase or an incomplete previous mutation; inspect its saved history and failure before any explicit repair. Do not automatically repeat a failed mutation.

Offboarding disables the account, removes its operator role, applies a deny only to the owned Ops resource and closes only sessions whose user is `CORP\iam.leaver`. Compare the retained stream and fresh-resource denial timestamps against DC `DisabledUtc`. Run `n.ps1` separately for online authentication with healthy controls. A generic network error is insufficient evidence of permission denial or disabled-account rejection.

## Failure recovery and cleanup

The intentional ops1 mistake is restored by adding only its original operator role, after actual denial is recorded. Do not substitute a membership listing for the subsequent successful file operations.

The original leaver probe's Dispose exception prevented fresh access testing. The fixed probe records the cleanup HRESULT and still tests a fresh read. The one-use `PrepareLeaverRetest` phase requires the original successful offboarding, a disabled role-free leaver and exactly its explicit deny rule. It removes only that rule, requires exact original Ops SDDL, restores only the original role and enables the synthetic account. `OffboardRetest` repeats the guarded targeted revocation under a distinct history entry. Keep both attempts; this retest is a repair path, not a phase to run routinely.

After verification, remove both transient host mappings on both guests and verify the empty folder lists. Close WS01's ISE session to end its Process-only execution policy setting. Retain protected local fixture secrets and demonstration resources; do not copy them into Git. A local editor session is not malware isolation, and none of these helpers downloads or executes third-party code.
