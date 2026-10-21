# Synthetic request and review register

These are fictional workflow records for the lab. Jake performed the requester, resource owner, administrator and reviewer personas; they do not demonstrate organizational separation of duties. This register was assembled after execution from the approved lab scope, fixture approval marker, controller decisions and observed results. The identifiers below are documentation labels, not tickets from a service-management platform. No historical independent approval timestamps are invented.

| Record | Synthetic request / owner decision | Actual implementation and verification |
| --- | --- | --- |
| J-01 | Onboard sec1/sec2/mover as readers; ops1/ops2/leaver as operators. Approve only the corresponding resource role. | Fixture export and joiner report: six nonadmin users, 24 expected allowed/denied operations. |
| M-01 | Transfer mover to operations; remove its obsolete Review role. | Move phase plus mover report: Review denied, Ops read/write allowed in refreshed user context. |
| L-01 | Offboard leaver, preserve its account for evidence, revoke owned resource access and address its active SMB session. | Offboard and OffboardRetest phases: account disabled, group removed, targeted NTFS deny applied, only leaver sessions closed. Passing retained/fresh-resource and separate online-authentication reports. |
| R-01 | Keep approved reader access for sec2; reject its extra operator role. | Seeded Ops read/write allowed; removal restored both denials in remediated report. |
| R-02 | Reject obsolete reader membership for the transferred mover. | Seeded Review read allowed; group removal restored denial while Ops access remained allowed. |
| R-03 | Reject sec2's direct Review NTFS Modify and SMB Change grants. | Seeded Review write allowed; exact NTFS baseline restored and direct SMB entry removed; write denied afterward. |
| R-04 | Remove retained operator entitlement from deliberately disabled ops2. | Seed phase disabled ops2 but retained its role; remediation removed the role. Later online tests rejected it with disabled-account code 1331. |
| RC-01 | Preserve ops1's legitimate operator access. Revert only the deliberate mistaken group removal. | Mistake report proves loss; Restore phase applies exact membership inverse; recovered report proves access in 43.14 seconds. |

R-01 through R-04 were deliberately planted and are closed within this lab scope. Legitimate access was retained for the remaining enabled users. Inactivity alone was not used as a production policy or an automatic entitlement-removal trigger.

The fixture's `SyntheticApproval` field and the remediation controller's recorded decisions are the underlying sources. [evidence/index.json](evidence/index.json) maps `fixture`, `phaseSeedReview`, `phaseRemediate`, the access stages and final offboarding evidence to their original files.
