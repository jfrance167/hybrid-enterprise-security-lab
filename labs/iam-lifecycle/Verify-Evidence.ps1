# Read-only verification of committed synthetic evidence. Never operates on a VM.
[CmdletBinding()]
param([string]$EvidenceDirectory=(Join-Path $PSScriptRoot 'evidence'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$run='96cb9aaf65ac4de698f7cf5af0e09ca8'
$index=Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'index.json') -Raw | ConvertFrom-Json
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Read-Evidence([string]$Key){
 $name=$index.$Key
 Assert ($name -match '^[a-zA-Z0-9-]+\.json$') 'Evidence index path must be a basename'
 $report=Get-Content -LiteralPath (Join-Path $EvidenceDirectory $name) -Raw | ConvertFrom-Json
 Assert ($report.RunId -ceq $run) ('Run mismatch: '+$Key)
 return $report
}
function Is-True($Value){return ($Value -is [bool] -and $Value)}
function Is-False($Value){return ($Value -is [bool] -and -not $Value)}
function Same-Names($Expected,$Actual){
 Assert (@(Compare-Object @($Expected | Sort-Object) @($Actual | Sort-Object)).Count -eq 0) 'Missing, extra or duplicate subjects/operations'
}
function Seconds($Later,$Earlier){
 # PowerShell 7.5 converts ISO JSON strings to DateTime. Avoid string coercion,
 # which uses a display format that loses fractional seconds.
 $end=if($Later -is [DateTime]){[DateTimeOffset]$Later}else{[DateTimeOffset]::Parse($Later)}
 $start=if($Earlier -is [DateTime]){[DateTimeOffset]$Earlier}else{[DateTimeOffset]::Parse($Earlier)}
 return ($end-$start).TotalSeconds
}
$reports=@{}
foreach($stage in @('joiner','mover','seeded','remediated','mistake','recovered','final')){
 $r=Read-Evidence $stage;$reports[$stage]=$r
 Assert ($r.Stage -ceq $stage) 'Incorrect stage'
 $names=@('CORP\iam.sec1','CORP\iam.sec2','CORP\iam.ops1','CORP\iam.mover')
 if($stage -ne 'final'){$names+=@('CORP\iam.leaver')}
 if($stage -in @('joiner','mover')){$names+=@('CORP\iam.ops2')}
 if($stage -eq 'mistake'){$names=@('CORP\iam.ops1')}
 Same-Names $names @($r.Subjects.Identity)
 $normalPass=$true
 foreach($subject in $r.Subjects){
  $role=if($subject.Identity -in @('CORP\iam.sec1','CORP\iam.sec2') -or ($stage -eq 'joiner' -and $subject.Identity -eq 'CORP\iam.mover')){'SecurityReader'}else{'SystemsOperator'}
  Assert ($subject.Role -ceq $role -and (Is-False $subject.AdministrativeToken)) 'Wrong role or administrative token'
  Same-Names @('Ops/Read','Ops/Write','Review/Read','Review/Write') @($subject.Operations | ForEach-Object {$_.Resource+'/'+$_.Operation})
  $subjectNormal=$true
  foreach($op in $subject.Operations){
   $normal=if(($role -eq 'SecurityReader' -and $op.Resource -eq 'Review' -and $op.Operation -eq 'Read') -or ($role -eq 'SystemsOperator' -and $op.Resource -eq 'Ops')){'ALLOW'}else{'DENY'}
   $observed=$normal
   if($stage -eq 'seeded' -and ($subject.Identity -eq 'CORP\iam.sec2' -or ($subject.Identity -eq 'CORP\iam.mover' -and $op.Resource -eq 'Review' -and $op.Operation -eq 'Read'))){$observed='ALLOW'}
   if($stage -eq 'mistake' -and $op.Resource -eq 'Ops'){$observed='DENY'}
   Assert ($op.Expected -ceq $normal -and $op.Actual -ceq $observed) ('Unexpected actual operation: '+$stage+'/'+$subject.Identity+'/'+$op.Resource+'/'+$op.Operation)
   if($observed -eq 'DENY'){Assert ($null -ne $op.ErrorCode -and ($op.ErrorCode -band 65535) -eq 5) 'Denial lacks Win32 access-denied code 5'}
   $passed=($normal -eq $observed)
   Assert ($op.Passed -is [bool] -and $op.Passed -eq $passed) 'Operation verdict inconsistent'
   $subjectNormal=$subjectNormal -and $passed
  }
  Assert ($subject.Passed -is [bool] -and $subject.Passed -eq $subjectNormal) 'Subject verdict inconsistent'
  $normalPass=$normalPass -and $subjectNormal
 }
 Assert ($r.Passed -is [bool] -and $r.Passed -eq $normalPass) 'Aggregate verdict inconsistent'
}
$phases=@{}
foreach($phase in @('Move','SeedReview','Remediate','Mistake','Restore','Offboard','PrepareLeaverRetest','OffboardRetest')){
 $p=Read-Evidence ('phase'+$phase);$phases[$phase]=$p
 Assert ($p.Phase -ceq $phase -and $p.Entry.Phase -ceq $phase -and $p.Entry.Status -ceq 'Succeeded' -and $null -eq $p.Entry.Failure) 'Incomplete directory phase'
 Assert ((Seconds $p.Entry.CompletedUtc $p.Entry.StartedUtc) -ge 0) 'Negative directory duration'
}
foreach($pair in @(@('mover','Move'),@('seeded','SeedReview'),@('remediated','Remediate'),@('mistake','Mistake'),@('recovered','Restore'),@('final','OffboardRetest'))){
 Assert ((Seconds $reports[$pair[0]].CompletedUtc $phases[$pair[1]].Entry.CompletedUtc) -ge 0) 'Resource evidence predates its phase'
}
$recovery=Seconds $reports.recovered.CompletedUtc $phases.Mistake.Entry.StartedUtc
Assert ($recovery -ge 0 -and $recovery -le 300) 'Actual access recovery missed 300-second target'
$review=@($phases.Remediate.After.Resources | Where-Object Resource -eq 'Review')
Assert ($review.Count -eq 1 -and $review[0].Sddl -ceq $phases.SeedReview.Entry.Details.ReviewBaselineSddl) 'Review baseline not restored exactly'
Assert (@($review[0].ShareAccess | Where-Object AccountName -eq 'CORP\iam.sec2').Count -eq 0) 'Seeded direct SMB grant remains'
$preparedOps=@($phases.PrepareLeaverRetest.After.Resources | Where-Object Resource -eq 'Ops')
Assert ($preparedOps[0].Sddl -ceq $phases.Offboard.Entry.Details.OpsBaselineSddl) 'Retest preparation changed original Ops baseline'
$session=Read-Evidence 'session'
Assert ($session.Identity -ceq 'CORP\iam.leaver' -and (Is-False $session.AdministrativeToken) -and $null -eq $session.Failure) 'Session context/failure invalid'
Assert ((Seconds $phases.OffboardRetest.Entry.Details.DisabledUtc $session.ReadyUtc) -ge 0) 'Session was not ready before disablement'
$held=Seconds $session.StreamFailedUtc $phases.OffboardRetest.Entry.Details.DisabledUtc
$fresh=Seconds $session.FreshReadUtc $phases.OffboardRetest.Entry.Details.DisabledUtc
Assert ($held -ge 0 -and $held -le 60 -and $fresh -ge 0 -and $fresh -le 60) 'Observed resource revocation missed 60-second target'
Assert ($session.FreshReadResult -ceq 'DENY' -and ($session.FreshReadErrorCode -band 65535) -eq 5) 'Fresh read lacks actual access-denied result'
Assert ((Is-True (Read-Evidence 'sessionParent').Passed) -and (Is-False (Read-Evidence 'firstSessionParent').Passed)) 'Original failure or passing retest missing'
Assert ((Read-Evidence 'firstSession').FreshReadResult -ceq 'NOT RUN' -and $null -ne (Read-Evidence 'firstSession').Failure) 'Original stream cleanup failure was overwritten'
$auth=Read-Evidence 'onlineAuth'
Assert (Is-True $auth.Passed) 'Online authentication failed'
Assert ($auth.Server -ceq 'DC01.corp.example.test:389' -and $auth.Subjects.Count -eq 4) 'Wrong online server/attempt count'
Assert (($auth.Subjects.Identity -join ',') -ceq 'CORP\iam.sec1,CORP\iam.ops2,CORP\iam.leaver,CORP\iam.sec1') 'Healthy before/after controls missing'
foreach($subject in $auth.Subjects){
 Assert (Is-True $subject.Passed) 'Online subject failed'
 if($subject.Identity -eq 'CORP\iam.sec1'){
  Assert ($subject.Actual -ceq 'ALLOW' -and (Is-True $subject.NetworkLogonAllowed) -and $subject.AttemptStep -ceq 'RootDseSearch') 'Healthy online DC control failed'
 }else{
  Assert ($subject.Actual -ceq 'AUTH_REJECTED' -and (Is-False $subject.NetworkLogonAllowed) -and $subject.NetworkLogonErrorCode -eq 1331 -and $subject.LdapErrorCode -eq 49) 'Disabled authentication was an unrelated failure'
 }
 Assert ((Seconds $subject.StartedUtc $phases.OffboardRetest.Entry.CompletedUtc) -ge 0) 'Online authentication predates retest'
}
$directory=Read-Evidence 'directory'
Assert ((Is-True $directory.Passed) -and $directory.PrivilegedGroupSids.Count -eq 8 -and @($directory.RecursiveAdminMatches).Count -eq 0) 'Recursive administrative check incomplete'
Same-Names @('iam.sec1','iam.sec2','iam.ops1','iam.ops2','iam.mover','iam.leaver') @($phases.OffboardRetest.After.Users.Name)
Same-Names @($phases.OffboardRetest.After.Users.Name) @($directory.Users.User)
$domainSid=$phases.OffboardRetest.After.Users[0].SID -replace '-\d+$',''
Assert ($domainSid -match '^S-1-5-21-\d+-\d+-\d+$') 'Invalid domain SID'
$expectedAdminSids=@('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551',"$domainSid-512","$domainSid-518","$domainSid-519")
Same-Names $expectedAdminSids @($directory.PrivilegedGroupSids)
foreach($user in $phases.OffboardRetest.After.Users){
 $enabled=($user.Name -notin @('iam.ops2','iam.leaver'))
 Assert ($user.Enabled -is [bool] -and $user.Enabled -eq $enabled -and $user.AdministrativeEntitlements -eq 0) 'Final enabled/admin state incorrect'
 $role=if($user.Name -in @('iam.sec1','iam.sec2')){'IAM-SecurityReader'}else{'IAM-SystemsOperator'}
 $expectedGroups=if($enabled){@('CN='+$role+',OU=IAM-Lifecycle-Lab,OU=Lab,DC=corp,DC=example,DC=test')}else{@()}
 Same-Names $expectedGroups @($user.DirectGroups)
 $proof=@($directory.Users | Where-Object User -CEQ $user.Name)
 $expectedRole=if($enabled){$role}else{''}
 Assert ($proof.Count -eq 1 -and (Is-False $proof[0].Admin) -and $proof[0].Enabled -is [bool] -and $proof[0].Enabled -eq $enabled -and $proof[0].Roles -ceq $expectedRole) 'Directory proof contradicts final state'
 Assert (($user.SID -replace '-\d+$','') -ceq $domainSid) 'Inconsistent domain SID'
}
Assert (Is-True (Read-Evidence 'provisionCleanup').Passed) 'Provisioning cleanup missing'
[pscustomobject]@{Passed=$true;ActualAccessRecoverySeconds=$recovery;HeldStreamRevocationSeconds=$held;FreshReadDenialSeconds=$fresh;HealthyFinalOperations=16;Scope='Recorded synthetic VM evidence; no live changes; hashes do not establish provenance'}
