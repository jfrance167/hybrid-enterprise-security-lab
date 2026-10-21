# API references and attribution

Microsoft documentation consulted during the exercise, October 12-13, 2026:

- [Active Directory security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups): resource group design and administrative-group distinctions.
- [LdapConnection](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection): explicit online connection/bind and timeout APIs.
- [LDAP channel binding and signing](https://github.com/MicrosoftDocs/windowsserverdocs/blob/main/WindowsServerDocs/identity/ad-ds/ldap-channel-binding.md): LDAP integrity/confidentiality context. The helper uses SASL Negotiate signing/sealing; it does not claim TLS/channel-binding verification.
- [LogonUser API](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/winbase/nf-winbase-logonusera.md): NETWORK logon type3 does not cache credentials. The helper calls the Unicode LogonUserW entry point.
- [Account disabled error1331](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/account-currently-disabled-system-error-1331): numeric disabled-account result.

The helpers were written for this lab using built-in APIs; no third-party implementation was copied. Existing Northstar source and documentation retain their MIT license and attribution. Codex and a local Ollama narrative draft contributed as disclosed in the README. ECC's locally installed reviewer checklist guided implementing-agent review; its implementation is not redistributed here.
