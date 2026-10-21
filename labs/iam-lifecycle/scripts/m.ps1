# Northstar owned-fixture lifecycle controller. AI-assisted, built-in AD/SMB APIs.
# Run locally in DC01 ISE after reviewing source. Default control is read-only Audit.
# Does not recreate accounts, reset passwords, restore snapshots or delete resources.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$run='96cb9aaf65ac4de698f7cf5af0e09ca8'
$root='C:\Northstar-IAM'
$ou='OU=IAM-Lifecycle-Lab,OU=Lab,DC=corp,DC=example,DC=test'
$evidence='\\VBOXSVR\IAM_Evidence'
$computer=Get-CimInstance Win32_ComputerSystem
if($computer.Name -ne 'DC01' -or $computer.Domain -ne 'corp.example.test' -or $computer.DomainRole -ne 5){throw 'DC01/PDC only.'}
Import-Module ActiveDirectory
$manifest=Get-Content -LiteralPath ($root+'\run.json') -Raw | ConvertFrom-Json
$marker='Northstar IAM synthetic lab '+$run
if($manifest.RunId -ne $run -or $manifest.Root -ne $root -or $manifest.OU -ne $ou -or $manifest.OwnerMarker -ne $marker -or $manifest.Status -ne 'Prepared'){throw 'Fixture manifest mismatch.'}
if((Get-ADOrganizationalUnit -Identity $ou -Properties Description).Description -ne $marker){throw 'OU ownership mismatch.'}
$names=@('iam.sec1','iam.sec2','iam.ops1','iam.ops2','iam.mover','iam.leaver')
$reader=Get-ADGroup IAM-SecurityReader -Properties Description
$operator=Get-ADGroup IAM-SystemsOperator -Properties Description
foreach($group in @($reader,$operator)){
 if($group.DistinguishedName -ne ('CN='+$group.Name+','+$ou) -or -not $group.Description.StartsWith($marker+' role ')){throw 'Group ownership mismatch.'}
}
foreach($name in $names){
 $user=Get-ADUser $name -Properties Description
 if($user.DistinguishedName -ne ('CN='+$name+','+$ou) -or -not $user.Description.StartsWith($marker+' fictional ')){throw 'User ownership mismatch.'}
}
foreach($resource in @('Review','Ops')){
 $share=Get-SmbShare -Name ('NorthstarIAM'+$resource)
 if($share.Path -ne ($root+'\'+$resource) -or $share.Description -ne $marker){throw 'Resource ownership mismatch.'}
 $item=Get-Item -LiteralPath $share.Path
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Unexpected resource reparse point.'}
 if(-not ([IO.File]::ReadAllText($share.Path+'\baseline.txt')).Contains($run)){throw 'Resource content mismatch.'}
}
if(Get-SmbShare -Name NorthstarIAMProvision -ErrorAction SilentlyContinue){throw 'Temporary provisioning share must be absent.'}
$control=Get-Content '\\VBOXSVR\IAM_Input\dc-control.json' -Raw | ConvertFrom-Json
$phases=@('Audit','Move','SeedReview','Remediate','Mistake','Restore','Offboard','PrepareLeaverRetest','OffboardRetest')
if($control.RunId -ne $run -or $control.Phase -notin $phases){throw 'Invalid controller phase.'}
$phase=$control.Phase
$historyPath=$root+'\lifecycle.json'
if(Test-Path $historyPath){
 $history=Get-Content $historyPath -Raw | ConvertFrom-Json
 if($history.RunId -ne $run){throw 'History run mismatch.'}
}else{$history=[pscustomobject]@{RunId=$run;Entries=@()}}
function Save-History {$history | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $historyPath -Encoding UTF8}
function Require-Phase([string]$Name){
 $entries=@($history.Entries | Where-Object {$_.Phase -eq $Name -and $_.Status -eq 'Succeeded'})
 if($entries.Count -ne 1){throw ('Required successful phase missing or ambiguous: '+$Name)}
 return $entries[0]
}
function Get-AccessEvidence([string]$Stage){
 $files=@(Get-ChildItem -LiteralPath $evidence -Filter ('access-'+$Stage+'-*.json') | Sort-Object LastWriteTimeUtc -Descending)
 if(-not $files.Count){throw ('Actual workstation evidence missing: '+$Stage)}
 $report=Get-Content $files[0].FullName -Raw | ConvertFrom-Json
 if($report.RunId -ne $run -or $report.Stage -ne $Stage){throw 'Access evidence run/stage mismatch.'}
 return $report
}
function Require-AccessPass([string]$Stage,[DateTime]$NotBefore=[DateTime]::MinValue){
 $report=Get-AccessEvidence $Stage
 if($Stage -notin @('joiner','mover','remediated','recovered')){throw 'Unknown passing evidence stage.'}
 $expectedNames=@('CORP\iam.sec1','CORP\iam.sec2','CORP\iam.ops1','CORP\iam.mover','CORP\iam.leaver')
 if($Stage -in @('joiner','mover')){$expectedNames+=@('CORP\iam.ops2')}
 if($report.Passed -isnot [bool] -or $true -cne $report.Passed -or @($report.Subjects).Count -ne $expectedNames.Count -or @(Compare-Object @($expectedNames | Sort-Object) @($report.Subjects.Identity | Sort-Object)).Count){throw ('Actual complete resource tests missing: '+$Stage)}
 if([DateTime]::Parse($report.CompletedUtc).ToUniversalTime() -lt $NotBefore.ToUniversalTime()){throw 'Access evidence predates required directory phase.'}
 foreach($subject in $report.Subjects){
  $role=if($subject.Identity -in @('CORP\iam.sec1','CORP\iam.sec2') -or ($subject.Identity -eq 'CORP\iam.mover' -and $Stage -eq 'joiner')){'SecurityReader'}else{'SystemsOperator'}
  if($subject.Passed -isnot [bool] -or $subject.AdministrativeToken -isnot [bool] -or $true -cne $subject.Passed -or $false -cne $subject.AdministrativeToken -or $subject.Role -ne $role -or @($subject.Operations).Count -ne 4){throw 'Incomplete ordinary-user permission proof.'}
  $pairs=@($subject.Operations | ForEach-Object {$_.Resource+'/'+$_.Operation} | Sort-Object)
  if(@(Compare-Object @('Ops/Read','Ops/Write','Review/Read','Review/Write') $pairs).Count){throw 'Missing or duplicate resource operations.'}
  foreach($operation in $subject.Operations){
   $expected=if(($role -eq 'SecurityReader' -and $operation.Resource -eq 'Review' -and $operation.Operation -eq 'Read') -or ($role -eq 'SystemsOperator' -and $operation.Resource -eq 'Ops')){'ALLOW'}else{'DENY'}
   if($operation.Passed -isnot [bool] -or $true -cne $operation.Passed -or $operation.Expected -ne $expected -or $operation.Actual -ne $expected){throw 'Incorrect role permission proof.'}
   if($expected -eq 'DENY' -and (($operation.ErrorCode -band 65535) -ne 5)){throw 'Denial lacks access-denied error code.'}
  }
 }
 return $report
}
function Assert-Membership([string]$Name,[string[]]$Expected,[bool]$Enabled=$true){
 $user=Get-ADUser $Name -Properties MemberOf,Enabled
 if($user.Enabled -ne $Enabled -or @(Compare-Object @($user.MemberOf | Sort-Object) @($Expected | Sort-Object)).Count){throw ('Unexpected enabled/group baseline: '+$Name)}
}
function Require-ObservedAccess([object]$Report,[string]$Identity,[string]$Resource,[string]$Operation,[string]$Actual){
 $subjects=@($Report.Subjects | Where-Object Identity -eq $Identity)
 if($subjects.Count -ne 1 -or $subjects[0].AdministrativeToken -isnot [bool] -or $false -cne $subjects[0].AdministrativeToken){throw 'Ordinary-user review evidence missing.'}
 $operations=@($subjects[0].Operations | Where-Object {$_.Resource -eq $Resource -and $_.Operation -eq $Operation})
 if($operations.Count -ne 1 -or $operations[0].Actual -ne $Actual){throw 'Required real access observation missing.'}
 if($Actual -eq 'DENY' -and ($operations[0].ErrorCode -band 65535) -ne 5){throw 'Observation was not an access-denied result.'}
}
function Get-PublicState {
 $users=foreach($name in $names){
  $user=Get-ADUser $name -Properties MemberOf,Enabled
  $groups=@(Get-ADPrincipalGroupMembership $user | Select-Object Name,@{n='SID';e={$_.SID.Value}})
  $privileged=@($groups | Where-Object {$_.SID -match '-(512|518|519)$' -or $_.SID -in @('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551')})
  if($privileged.Count){throw ('Unexpected administrative entitlement: '+$name)}
  @{Name=$name;SID=$user.SID.Value;Enabled=$user.Enabled;DirectGroups=@($user.MemberOf);ResolvedGroups=$groups;AdministrativeEntitlements=$privileged.Count}
 }
 $resources=foreach($resource in @('Review','Ops')){
  @{Resource=$resource;Sddl=(Get-Acl ($root+'\'+$resource)).Sddl;ShareAccess=@(Get-SmbShareAccess ('NorthstarIAM'+$resource) | Select-Object AccountName,@{n='Type';e={$_.AccessControlType.ToString()}},@{n='Right';e={$_.AccessRight.ToString()}})}
 }
 return @{Users=@($users);Resources=@($resources)}
}
$before=Get-PublicState
$entry=[pscustomobject]@{Phase=$phase;Status='Started';StartedUtc=[DateTime]::UtcNow.ToString('o');CompletedUtc=$null;Details=@{};Failure=$null}
if($phase -ne 'Audit'){
 if(@($history.Entries | Where-Object {$_.Phase -eq $phase}).Count){throw 'Phase already attempted; inspect partial history before repair. No automatic rerun.'}
 if(@($history.Entries | Where-Object {$_.Status -ne 'Succeeded'}).Count){throw 'Prior incomplete phase requires explicit repair.'}
}
try{
 switch($phase){
  'Audit' {$entry.Details=@{Scope='Read-only current owned fixture state';ResourceTests='Separate workstation evidence required'}}
  'Move' {
   $proof=Require-AccessPass 'joiner'
   if(@($proof.Subjects).Count -ne 6){throw 'Joiner requires all six fixture users.'}
   Assert-Membership 'iam.mover' @($reader.DistinguishedName)
   $history.Entries+=@($entry);Save-History
   Remove-ADGroupMember $reader -Members iam.mover -Confirm:$false
   Add-ADGroupMember $operator -Members iam.mover
   Assert-Membership 'iam.mover' @($operator.DistinguishedName)
   $entry.Details=@{User='iam.mover';ApprovedOldRole='SecurityReader';ApprovedNewRole='SystemsOperator';ClientRetest='mover'}
  }
  'SeedReview' {
   $move=Require-Phase 'Move';$null=Require-AccessPass 'mover' ([DateTime]::Parse($move.CompletedUtc))
   Assert-Membership 'iam.sec2' @($reader.DistinguishedName)
   Assert-Membership 'iam.mover' @($operator.DistinguishedName)
   Assert-Membership 'iam.ops2' @($operator.DistinguishedName)
   $sid=(Get-ADUser iam.sec2).SID
   $acl=Get-Acl ($root+'\Review')
   if(@($acl.Access | Where-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid.Value}).Count){throw 'Unexpected existing direct grant.'}
   if(@(Get-SmbShareAccess NorthstarIAMReview | Where-Object AccountName -eq 'CORP\iam.sec2').Count){throw 'Unexpected direct SMB grant.'}
   $entry.Details=@{ReviewBaselineSddl=$acl.Sddl;Findings=@('iam.sec2 excessive Ops group','iam.mover obsolete Review group','iam.sec2 direct Review Modify/Change','iam.ops2 disabled with retained Ops entitlement')}
   $history.Entries+=@($entry);Save-History
   Add-ADGroupMember $operator -Members iam.sec2
   Add-ADGroupMember $reader -Members iam.mover
   $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'Modify','ContainerInherit,ObjectInherit','None','Allow')
   $null=$acl.AddAccessRule($rule);Set-Acl ($root+'\Review') $acl
   $null=Grant-SmbShareAccess NorthstarIAMReview -AccountName 'CORP\iam.sec2' -AccessRight Change -Force
   Disable-ADAccount iam.ops2
   Assert-Membership 'iam.sec2' @($reader.DistinguishedName,$operator.DistinguishedName)
   Assert-Membership 'iam.mover' @($reader.DistinguishedName,$operator.DistinguishedName)
   Assert-Membership 'iam.ops2' @($operator.DistinguishedName) $false
  }
  'Remediate' {
   $seed=Require-Phase 'SeedReview'
   $observed=Get-AccessEvidence 'seeded'
   if([DateTime]::Parse($observed.CompletedUtc).ToUniversalTime() -lt [DateTime]::Parse($seed.CompletedUtc).ToUniversalTime()){throw 'Seeded permission evidence is stale.'}
   Require-ObservedAccess $observed 'CORP\iam.sec2' 'Ops' 'Read' 'ALLOW'
   Require-ObservedAccess $observed 'CORP\iam.sec2' 'Ops' 'Write' 'ALLOW'
   Require-ObservedAccess $observed 'CORP\iam.sec2' 'Review' 'Write' 'ALLOW'
   Require-ObservedAccess $observed 'CORP\iam.mover' 'Review' 'Read' 'ALLOW'
   Assert-Membership 'iam.sec2' @($reader.DistinguishedName,$operator.DistinguishedName)
   Assert-Membership 'iam.mover' @($reader.DistinguishedName,$operator.DistinguishedName)
   Assert-Membership 'iam.ops2' @($operator.DistinguishedName) $false
   $entry.Details=@{Decisions=@('Remove unapproved Ops membership from sec2','Remove obsolete Review membership from mover','Remove seeded direct Review grant from sec2','Remove retained Ops membership from disabled ops2');ClientRetest='remediated'}
   $history.Entries+=@($entry);Save-History
   Remove-ADGroupMember $operator -Members iam.sec2,iam.ops2 -Confirm:$false
   Remove-ADGroupMember $reader -Members iam.mover -Confirm:$false
   $sid=(Get-ADUser iam.sec2).SID
   $acl=Get-Acl ($root+'\Review')
   $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'Modify','ContainerInherit,ObjectInherit','None','Allow')
   $acl.RemoveAccessRuleSpecific($rule);Set-Acl ($root+'\Review') $acl
   Revoke-SmbShareAccess NorthstarIAMReview -AccountName 'CORP\iam.sec2' -Force
   if((Get-Acl ($root+'\Review')).Sddl -ne $seed.Details.ReviewBaselineSddl){throw 'Review ACL baseline not restored exactly.'}
   if(@(Get-SmbShareAccess NorthstarIAMReview | Where-Object AccountName -eq 'CORP\iam.sec2').Count){throw 'Direct SMB grant remains.'}
   Assert-Membership 'iam.sec2' @($reader.DistinguishedName)
   Assert-Membership 'iam.mover' @($operator.DistinguishedName)
   Assert-Membership 'iam.ops2' @() $false
  }
  'Mistake' {
   $remediate=Require-Phase 'Remediate';$null=Require-AccessPass 'remediated' ([DateTime]::Parse($remediate.CompletedUtc))
   Assert-Membership 'iam.ops1' @($operator.DistinguishedName)
   $entry.Details=@{User='iam.ops1';Inverse='Re-add only IAM-SystemsOperator';RecoveryTargetSeconds=300}
   $history.Entries+=@($entry);Save-History
   Remove-ADGroupMember $operator -Members iam.ops1 -Confirm:$false
   Assert-Membership 'iam.ops1' @()
  }
  'Restore' {
   $mistake=Require-Phase 'Mistake';$proof=Get-AccessEvidence 'mistake'
   if([DateTime]::Parse($proof.CompletedUtc).ToUniversalTime() -lt [DateTime]::Parse($mistake.CompletedUtc).ToUniversalTime()){throw 'Actual lost-access evidence predates mistake.'}
   Require-ObservedAccess $proof 'CORP\iam.ops1' 'Ops' 'Read' 'DENY'
   Require-ObservedAccess $proof 'CORP\iam.ops1' 'Ops' 'Write' 'DENY'
   Assert-Membership 'iam.ops1' @()
   $history.Entries+=@($entry);Save-History
   Add-ADGroupMember $operator -Members iam.ops1
   Assert-Membership 'iam.ops1' @($operator.DistinguishedName)
   $elapsed=([DateTime]::UtcNow-[DateTime]::Parse($mistake.StartedUtc).ToUniversalTime()).TotalSeconds
   $entry.Details=@{MembershipRestoreSeconds=$elapsed;MembershipWithinTarget=($elapsed -le 300);ClientRetest='recovered';ActualAccessRecovery='Measure recovered workstation result timestamp against Mistake.StartedUtc; membership restoration alone is insufficient'}
  }
  'PrepareLeaverRetest' {
   # One owned-fixture retest after the preserved broken-stream Dispose failure.
   $original=Require-Phase 'Offboard'
   Assert-Membership 'iam.leaver' @() $false
   $sid=(Get-ADUser iam.leaver).SID
   $acl=Get-Acl ($root+'\Ops')
   $denies=@($acl.Access | Where-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid.Value -and $_.AccessControlType -eq 'Deny'})
   if($denies.Count -ne 1 -or $denies[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::Modify -or $denies[0].IsInherited){throw 'Unexpected leaver deny; no retest preparation.'}
   $entry.Details=@{Reason='Verify fixed broken-stream cleanup using same fictional subject';OriginalOffboardUtc=$original.CompletedUtc;ExpectedFinalState='Disabled; no role membership; targeted Ops deny'}
   $history.Entries+=@($entry);Save-History
   $acl.RemoveAccessRuleSpecific($denies[0]);Set-Acl ($root+'\Ops') $acl
   if((Get-Acl ($root+'\Ops')).Sddl -ne $original.Details.OpsBaselineSddl){throw 'Exact original Ops baseline was not restored.'}
   Add-ADGroupMember $operator -Members iam.leaver
   Enable-ADAccount iam.leaver
   Assert-Membership 'iam.leaver' @($operator.DistinguishedName)
  }
  {$_ -in @('Offboard','OffboardRetest')} {
   if($phase -eq 'OffboardRetest'){$null=Require-Phase 'PrepareLeaverRetest'}
   $restore=Require-Phase 'Restore';$recovered=Require-AccessPass 'recovered' ([DateTime]::Parse($restore.CompletedUtc))
   $mistake=Require-Phase 'Mistake'
   $recoverySeconds=([DateTime]::Parse($recovered.CompletedUtc).ToUniversalTime()-[DateTime]::Parse($mistake.StartedUtc).ToUniversalTime()).TotalSeconds
   if($recoverySeconds -lt 0 -or $recoverySeconds -gt 300){throw 'Actual access recovery missed the five-minute target; preserve and review this failure.'}
   Assert-Membership 'iam.leaver' @($operator.DistinguishedName)
   $ready=Get-Content ($evidence+'\leaver-ready-'+$run+'.json') -Raw | ConvertFrom-Json
   $readyAge=([DateTime]::UtcNow-[DateTime]::Parse($ready.ReadyUtc).ToUniversalTime()).TotalSeconds
   if($ready.RunId -ne $run -or $ready.Identity -ne 'CORP\iam.leaver' -or -not $ready.Ready -or $readyAge -lt 0 -or $readyAge -gt 120){throw 'Fresh live ordinary-user retained-session readiness required.'}
   if(@(Get-SmbSession | Where-Object ClientUserName -eq 'CORP\iam.leaver').Count -lt 1){throw 'Active fictional leaver SMB session missing; do not mutate yet.'}
   $sid=(Get-ADUser iam.leaver).SID
   $entry.Details=@{OpsBaselineSddl=(Get-Acl ($root+'\Ops')).Sddl;DisabledUtc=$null;GroupsRemovedUtc=$null;DenyAppliedUtc=$null;SessionsClosedUtc=$null;SessionCount=0;SessionIds=@();Scope='Only fictional leaver and owned Ops resource; no global TGT revocation claim'}
   $history.Entries+=@($entry);Save-History
   Disable-ADAccount iam.leaver
   $entry.Details.DisabledUtc=[DateTime]::UtcNow.ToString('o');Save-History
   Remove-ADGroupMember $operator -Members iam.leaver -Confirm:$false
   $entry.Details.GroupsRemovedUtc=[DateTime]::UtcNow.ToString('o');Save-History
   $acl=Get-Acl ($root+'\Ops')
   $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'Modify','ContainerInherit,ObjectInherit','None','Deny')
   $null=$acl.AddAccessRule($rule);Set-Acl ($root+'\Ops') $acl
   $entry.Details.DenyAppliedUtc=[DateTime]::UtcNow.ToString('o');Save-History
   $sessions=@(Get-SmbSession | Where-Object ClientUserName -eq 'CORP\iam.leaver')
   $entry.Details.SessionCount=$sessions.Count;$entry.Details.SessionIds=@($sessions | ForEach-Object SessionId)
   foreach($session in $sessions){Close-SmbSession -SessionId $session.SessionId -Force}
   $entry.Details.SessionsClosedUtc=[DateTime]::UtcNow.ToString('o')
   Assert-Membership 'iam.leaver' @() $false
  }
 }
 $entry.Status='Succeeded';$entry.CompletedUtc=[DateTime]::UtcNow.ToString('o')
 $after=Get-PublicState
}catch{
 $entry.Status='Failed';$entry.CompletedUtc=[DateTime]::UtcNow.ToString('o');$entry.Failure=$_.Exception.Message
 $after=$null
}finally{
 if($phase -ne 'Audit'){Save-History}
 @{RunId=$run;Phase=$phase;Entry=$entry;Before=$before;After=$after;RuntimeResourceTests='See separate workstation operations, not this controller success'} | ConvertTo-Json -Depth 12 | Set-Content ($evidence+'\phase-'+$phase+'-'+[Guid]::NewGuid().ToString('N')+'.json') -Encoding UTF8
}
if($entry.Status -ne 'Succeeded'){throw ('Phase failed; inspect saved evidence and partial owned history: '+$phase)}
Write-Host ('Owned-fixture phase '+$phase+' succeeded. Actual workstation access assertions still required.')
