# Northstar isolated IAM fixture setup. AI-assisted; built-in Windows/AD APIs.
# Run once in DC01. Refuses pre-existing fixture identifiers. Never deletes objects.
[CmdletBinding()]
param([string]$EvidenceDirectory='\\VBOXSVR\IAM_Evidence')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Scoped analyzer exception: passwords below are RNG-generated for six fictional
# users and retained only in Administrators/SYSTEM-protected guest storage.
# This explicit lab design is not a production credential-storage recommendation.
function Convert-PrivateLabPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText','',Justification='RNG-generated isolated fixture password; AD requires SecureString; private guest storage is ACL-protected and excluded from evidence.')]
    [CmdletBinding()]
    param([string]$Password)
    ConvertTo-SecureString -String $Password -AsPlainText -Force
}
$computer=Get-CimInstance Win32_ComputerSystem
if($computer.Name -ne 'DC01' -or $computer.Domain -ne 'corp.example.test' -or $computer.DomainRole -ne 5){throw 'Restricted to Northstar DC01/PDC.'}
Import-Module ActiveDirectory
$domain=Get-ADDomain
if($domain.DNSRoot -ne 'corp.example.test' -or $domain.NetBIOSName -ne 'CORP'){throw 'Wrong directory.'}
if(-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)){throw 'Evidence share unavailable.'}
$parent='OU=Lab,DC=corp,DC=example,DC=test'
$null=Get-ADOrganizationalUnit -Identity $parent
$ou='OU=IAM-Lifecycle-Lab,'+$parent
$root='C:\Northstar-IAM'
$users=@(
    @{Name='iam.sec1';Role='SecurityReader'},@{Name='iam.sec2';Role='SecurityReader'},
    @{Name='iam.ops1';Role='SystemsOperator'},@{Name='iam.ops2';Role='SystemsOperator'},
    @{Name='iam.mover';Role='SecurityReader'},@{Name='iam.leaver';Role='SystemsOperator'}
)
$groups=@{SecurityReader='IAM-SecurityReader';SystemsOperator='IAM-SystemsOperator'}
$shares=@{Review='NorthstarIAMReview';Ops='NorthstarIAMOps'}
$provisionShare='NorthstarIAMProvision'
if(Test-Path -LiteralPath $root){throw 'Fixture root already exists; inspect its manifest instead of recreating.'}
if(Get-ADOrganizationalUnit -LDAPFilter '(ou=IAM-Lifecycle-Lab)' -SearchBase $parent){throw 'Fixture OU exists; preserve and reconcile it.'}
foreach($user in $users){if(Get-ADUser -Filter "SamAccountName -eq '$($user.Name)'"){throw "Identity collision: $($user.Name)"}}
foreach($name in $groups.Values){if(Get-ADGroup -Filter "SamAccountName -eq '$name'"){throw "Group collision: $name"}}
foreach($name in $shares.Values){if(Get-SmbShare -Name $name -ErrorAction SilentlyContinue){throw "Share collision: $name"}}
if(Get-SmbShare -Name $provisionShare -ErrorAction SilentlyContinue){throw 'Provisioning share collision.'}
$run=[Guid]::NewGuid().ToString('N')
$private=Join-Path $root 'Private'
$manifestPath=Join-Path $root 'run.json'
$adminSid=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$systemSid=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
function Protect-Directory {
    param([string]$Path)
    $null=New-Item -Path $Path -ItemType Directory
    $acl=New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($adminSid)
    foreach($sid in @($adminSid,$systemSid)){
        $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $null=$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
Protect-Directory $root
Protect-Directory $private
$manifest=[ordered]@{SchemaVersion=1;RunId=$run;Domain='corp.example.test';OU=$ou;Root=$root;OwnerMarker=('Northstar IAM synthetic lab '+$run);Status='Preparing';StartedUtc=[DateTime]::UtcNow.ToString('o');Groups=$groups;Shares=$shares;Users=$users;Created=@();Failure=$null}
function Save-Manifest { $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8 }
Save-Manifest
$secrets=[ordered]@{SchemaVersion=1;RunId=$run;Domain='CORP';Users=@()}
$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
try{
    foreach($user in $users){
        $bytes=New-Object byte[] 24
        $rng.GetBytes($bytes)
        $password=[Convert]::ToBase64String($bytes)+'aA1!'
        $secrets.Users+=@{Name=$user.Name;Password=$password}
    }
}finally{$rng.Dispose()}
# Private data stays in this explicitly protected guest directory, outside evidence.
$secrets | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $private 'credentials.json') -Encoding UTF8
try{
    New-ADOrganizationalUnit -Name 'IAM-Lifecycle-Lab' -Path $parent -Description $manifest.OwnerMarker -ProtectedFromAccidentalDeletion $true
    $manifest.Created+=@{Type='OU';Identity=$ou};Save-Manifest
    foreach($role in @('SecurityReader','SystemsOperator')){
        New-ADGroup -Name $groups[$role] -SamAccountName $groups[$role] -GroupScope Global -GroupCategory Security -Path $ou -Description ($manifest.OwnerMarker+' role '+$role)
        $manifest.Created+=@{Type='Group';Identity=$groups[$role]};Save-Manifest
    }
    foreach($user in $users){
        $entry=@($secrets.Users | Where-Object Name -eq $user.Name)
        if($entry.Count -ne 1){throw 'Private credential manifest mismatch.'}
        $secure=Convert-PrivateLabPassword -Password $entry[0].Password
        New-ADUser -Name $user.Name -SamAccountName $user.Name -UserPrincipalName ($user.Name+'@corp.example.test') -Path $ou -Description ($manifest.OwnerMarker+' fictional '+$user.Role) -AccountPassword $secure -Enabled $true -ChangePasswordAtLogon $false -PasswordNeverExpires $false
        $manifest.Created+=@{Type='User';Identity=$user.Name};Save-Manifest
        Add-ADGroupMember -Identity $groups[$user.Role] -Members $user.Name
    }
    foreach($resource in @('Review','Ops')){
        $path=Join-Path $root $resource
        Protect-Directory $path
        $role=if($resource -eq 'Review'){'SecurityReader'}else{'SystemsOperator'}
        $sid=(Get-ADGroup -Identity $groups[$role]).SID
        $rights=if($resource -eq 'Review'){'ReadAndExecute'}else{'Modify'}
        $acl=Get-Acl -LiteralPath $path
        $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$rights,'ContainerInherit,ObjectInherit','None','Allow')
        $null=$acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $path -AclObject $acl
        Set-Content -LiteralPath (Join-Path $path 'baseline.txt') -Value ('Synthetic '+$resource+' material, run '+$run) -Encoding UTF8
        $access=@{Name=$shares[$resource];Path=$path;Description=$manifest.OwnerMarker;FullAccess='CORP\Domain Admins'}
        if($resource -eq 'Review'){$access.ReadAccess='CORP\'+$groups[$role]}else{$access.ChangeAccess='CORP\'+$groups[$role]}
        $null=New-SmbShare @access
        $manifest.Created+=@{Type='Share';Identity=$shares[$resource];Path=$path};Save-Manifest
    }
    # Temporary encrypted admin-only transfer to protected WS storage.
    # Remove this owned provisioning share before ordinary-user access tests.
    $null=New-SmbShare -Name $provisionShare -Path $private -Description $manifest.OwnerMarker -FullAccess 'CORP\Domain Admins' -EncryptData $true
    $manifest.Created+=@{Type='ProvisioningShare';Identity=$provisionShare;Path=$private};Save-Manifest
    $manifest.Status='Prepared';$manifest.CompletedUtc=[DateTime]::UtcNow.ToString('o');Save-Manifest
}catch{
    $manifest.Status='Partial';$manifest.Failure=$_.Exception.Message;Save-Manifest
    throw 'Fixture setup incomplete. Inspect owned run manifest; do not delete or reset unrelated objects.'
}finally{$secrets=$null;$password=$null;$secure=$null;$entry=$null}
$userEvidence=foreach($user in $users){Get-ADUser -Identity $user.Name -Properties MemberOf,Enabled | Select-Object SamAccountName,DistinguishedName,Enabled,SID,MemberOf}
$resourceEvidence=foreach($resource in @('Review','Ops')){
    $path=Join-Path $root $resource
    [ordered]@{Resource=$resource;Path=$path;Sddl=(Get-Acl -LiteralPath $path).Sddl;Share=$shares[$resource];ShareAccess=@(Get-SmbShareAccess -Name $shares[$resource] | Select-Object AccountName,AccessControlType,AccessRight)}
}
$evidence=[ordered]@{SchemaVersion=1;Stage='Fixture prepared, user access tests pending';RunId=$run;CompletedUtc=[DateTime]::UtcNow.ToString('o');Domain='corp.example.test';OU=$ou;Users=@($userEvidence);Resources=@($resourceEvidence);SyntheticApproval='Jake performs fictional requester, resource owner and administrator roles; no real employee or employer data';AdminMembershipCheck='User direct/transitive administrative membership assertions remain required'}
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory ('fixture-'+$run+'.json')) -Encoding UTF8
Write-Host 'Isolated fixture prepared. Secrets remain in protected guest storage. Actual ordinary-user resource tests are required.'
