# Security notice

This is an educational, fictional VirtualBox lab, not a production security
architecture. The source contains no VM disks, installation images, live
credentials, raw event logs, or customer data. Keep the VMs on isolated NAT and
internal networks; never bridge them to a school, employer, or home production
network.

The initial firewall setup script requires an explicit installation flag and
refuses to run after the scoped allowlist exists. The running lab uses that
allowlist; the four temporary broad passes are disabled. Approved application,
domain, and telemetry flows and two denied cross-segment flows were tested.
The rule matrix and remaining gaps are in [FIREWALL_POLICY.md](FIREWALL_POLICY.md). The selected
ISO/IEC 27001:2022 controls, evidence, and open gaps are recorded in
[ISO27001_CONTROL_MAPPING.md](ISO27001_CONTROL_MAPPING.md); this lab is not
certified. The internal service uses HTTP and management certificates are
self-signed; firewall Syslog uses unencrypted UDP on the isolated management
network. Do not reuse these settings
for real data or an Internet-facing system.

Use only synthetic identities and safe events. Review every screenshot and
export before publication. Store passwords and recovery answers outside Git,
rotate any accidentally exposed value, and report unintended exposures through
GitHub private vulnerability reporting if this project is published.
