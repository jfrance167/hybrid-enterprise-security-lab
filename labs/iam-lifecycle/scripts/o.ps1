# Read-only directory proof and concise on-screen evidence for the owned fixture.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$run='96cb9aaf65ac4de698f7cf5af0e09ca8'
$ou='OU=IAM-Lifecycle-Lab,OU=Lab,DC=corp,DC=example,DC=test'
if($env:COMPUTERNAME -ne 'DC01'){throw 'Owned DC01 only.'}
Import-Module ActiveDirectory
$manifest=Get-Content 'C:\Northstar-IAM\run.json' -Raw | ConvertFrom-Json
if($manifest.RunId -ne $run -or $manifest.OU -ne $ou -or (Get-ADOrganizationalUnit $ou -Properties Description).Description -ne ('Northstar IAM synthetic lab '+$run)){throw 'Fixture ownership mismatch.'}
$names=@('iam.sec1','iam.sec2','iam.ops1','iam.ops2','iam.mover','iam.leaver')
$domain=Get-ADDomain
if($domain.DNSRoot -ne 'corp.example.test'){throw 'Owned domain only.'}
$adminGroups=@(512,518,519 | ForEach-Object {$domain.DomainSID.Value+'-'+$_})
$adminGroups+=@('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551')
$matches=@()
foreach($sid in $adminGroups){
 $members=@(Get-ADGroupMember -Identity $sid -Recursive)
 foreach($member in $members){if($member.SamAccountName -in $names){$matches+=@{User=$member.SamAccountName;PrivilegedGroupSid=$sid}}}
}
if($matches.Count){throw 'Unexpected direct or nested administrative membership.'}
$rows=foreach($name in $names){
 $user=Get-ADUser $name -Properties Enabled,MemberOf,Description
 if($user.DistinguishedName -ne ('CN='+$name+','+$ou) -or -not $user.Description.StartsWith('Northstar IAM synthetic lab '+$run+' fictional ')){throw 'Subject ownership mismatch.'}
 $roles=@($user.MemberOf | ForEach-Object {(Get-ADGroup -Identity $_).Name})
 [pscustomobject]@{User=$name;Enabled=$user.Enabled;Roles=($roles -join ',');Admin=$false}
}
$report=@{RunId=$run;OU=$ou;CompletedUtc=[DateTime]::UtcNow.ToString('o');Users=@($rows);PrivilegedGroupSids=$adminGroups;RecursiveAdminMatches=$matches;Passed=$true}
$file='directory-proof-'+[Guid]::NewGuid().ToString('N')+'.json'
$report | ConvertTo-Json -Depth 6 | Set-Content ('\\VBOXSVR\IAM_Evidence\'+$file) -Encoding UTF8
Clear-Host
Write-Host 'NORTHSTAR IAM | Final owned directory state'
Write-Host ('UTC '+$report.CompletedUtc)
Write-Host 'OU: IAM-Lifecycle-Lab / Lab / corp.example.test'
$rows | Format-Table User,Enabled,Roles,Admin -AutoSize
Write-Host ('Recursive checks: '+$adminGroups.Count+' administrative groups; matches 0')
Write-Host ('Source '+$file)
