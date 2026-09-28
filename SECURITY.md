# Security notice

This is an educational, fictional VirtualBox lab, not a production security
architecture. The source contains no VM disks, installation images, live
credentials, raw event logs, or customer data. Keep the VMs on isolated NAT and
internal networks; never bridge them to a school, employer, or home production
network.

The firewall setup script adds broad outbound rules only with an explicit
installation flag. The running lab currently has those temporary rules. Narrow
them, verify denied cross-segment traffic, and capture sanitized evidence before
claiming the network-control deliverable is complete. The internal service uses
HTTP and management certificates are self-signed. Do not reuse these settings
for real data or an Internet-facing system.

Use only synthetic identities and safe events. Review every screenshot and
export before publication. Store passwords and recovery answers outside Git,
rotate any accidentally exposed value, and report unintended exposures through
GitHub private vulnerability reporting if this project is published.
