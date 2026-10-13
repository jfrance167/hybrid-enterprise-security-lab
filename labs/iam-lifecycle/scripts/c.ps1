# Administrator orchestrates isolated fresh domain-user processes; secrets remain local.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Scoped analyzer exception: the six random fictional fixture passwords are read
# only after verifying Administrators/SYSTEM ACLs below. No literal secret or
# production credential is accepted; conversion does not make plaintext storage safe.
function Convert-PrivateLabPassword {
 [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText','',Justification='Isolated random fixture credentials from ACL-validated private guest storage; required by Start-Process -Credential; never logged or exported as evidence.')]
 [CmdletBinding()]
 param([string]$Password)
 ConvertTo-SecureString $Password -AsPlainText -Force
}
$computer=Get-CimInstance Win32_ComputerSystem
if($computer.Name -ne 'WS01' -or $computer.Domain -ne 'corp.example.test' -or -not $computer.PartOfDomain){throw 'Northstar WS01 domain member only'}
$root='C:\Northstar-IAM-Client'
$m=Get-Content ($root+'\run.json') -Raw | ConvertFrom-Json
if($m.RunId -ne '96cb9aaf65ac4de698f7cf5af0e09ca8'){throw 'Wrong run'}
$control=Get-Content '\\VBOXSVR\IAM_Input\client-control.json' -Raw | ConvertFrom-Json
if($control.RunId -ne $m.RunId -or $control.Stage -notmatch '^[a-zA-Z0-9-]{1,40}$'){throw 'Invalid control'}
if(@($control.Subjects).Count -lt 1 -or @($control.Subjects).Count -gt 6 -or @($control.Subjects.Name | Select-Object -Unique).Count -ne @($control.Subjects).Count){throw 'Subject list must contain one to six unique users'}
$retained=($control.Stage -eq 'leaver-session')
if($retained -and (@($control.Subjects).Count -ne 1 -or $control.Subjects[0].Name -ne 'iam.leaver' -or $control.Subjects[0].Role -ne 'SystemsOperator')){throw 'Retained session is restricted to the fictional leaver.'}
$privatePath=$root+'\Private\credentials.json'
foreach($privateItem in @((Join-Path $root 'Private'),$privatePath)){
 $privateAcl=Get-Acl -LiteralPath $privateItem
 if($privateItem -eq ($root+'\Private') -and -not $privateAcl.AreAccessRulesProtected){throw 'Private directory inheritance protection lost.'}
 foreach($rule in $privateAcl.Access){if($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Unexpected private ACL principal.'}}
}
$private=Get-Content $privatePath -Raw | ConvertFrom-Json
if($private.RunId -ne $m.RunId -or $private.Domain -ne 'CORP' -or $private.SchemaVersion -ne 1){throw 'Private data schema/run mismatch.'}
$admin=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$users=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
function Set-OwnedAcl([string]$Path,$UserSid,$Rights,[bool]$Inherit){
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($admin)
 foreach($sid in @($admin,$system)){$null=$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
 $flags=if($Inherit){'ContainerInherit,ObjectInherit'}else{'None'}
 $null=$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($UserSid,$Rights,$flags,'None','Allow')))
 Set-Acl -LiteralPath $Path -AclObject $acl
}
Set-OwnedAcl $root $users 'ReadAndExecute' $false
$scripts=$root+'\Scripts';$results=$root+'\Results'
foreach($path in @($scripts,$results)){if(-not(Test-Path $path)){$null=New-Item $path -ItemType Directory}}
Set-OwnedAcl $scripts $users 'ReadAndExecute' $true
Set-OwnedAcl $results $users 'ReadAndExecute' $false
$probeFile=if($retained){'l.ps1'}else{'e.ps1'}
Copy-Item ('\\VBOXSVR\IAM_Input\'+$probeFile) ($scripts+'\'+$probeFile) -Force
$reports=@()
foreach($subject in $control.Subjects){
 if($subject.Name -notin @('iam.sec1','iam.sec2','iam.ops1','iam.ops2','iam.mover','iam.leaver') -or $subject.Role -notin @('SecurityReader','SystemsOperator')){throw 'Unknown subject'}
 $entry=@($private.Users | Where-Object Name -eq $subject.Name)
 if($entry.Count -ne 1){throw 'Private credential mismatch'}
 $sid=(New-Object Security.Principal.NTAccount('CORP',$subject.Name)).Translate([Security.Principal.SecurityIdentifier])
 $attempt=$results+'\'+[Guid]::NewGuid().ToString('N')
 $null=New-Item $attempt -ItemType Directory
 Set-OwnedAcl $attempt $sid 'Modify' $true
 $output=$attempt+'\result.json'
 $credential=New-Object Management.Automation.PSCredential(('CORP\'+$subject.Name),(Convert-PrivateLabPassword -Password $entry[0].Password))
 $probeArguments='-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$scripts+'\'+$probeFile+'" -Name '+$subject.Name+' -Role '+$subject.Role+' -RunId '+$m.RunId+' -ResultPath "'+$output+'"'
 $process=$null
 try{
  $process=Start-Process ($env:SystemRoot+'\System32\WindowsPowerShell\v1.0\powershell.exe') -Credential $credential -ArgumentList $probeArguments -PassThru -WindowStyle Hidden
  $credential=$null;$entry=$null
  if($retained){
   $watch=[Diagnostics.Stopwatch]::StartNew();$published=$false
   while(-not $process.WaitForExit(1000)){
    if(-not $published -and (Test-Path ($output+'.ready.json'))){
     $ready=Get-Content ($output+'.ready.json') -Raw | ConvertFrom-Json
     if($ready.RunId -ne $m.RunId -or $ready.Identity -ne 'CORP\iam.leaver' -or -not $ready.Ready -or -not $ready.InitialReadWriteVerified){throw 'Invalid retained-session readiness.'}
     $ready | ConvertTo-Json | Set-Content ('\\VBOXSVR\IAM_Evidence\leaver-ready-'+$m.RunId+'.json') -Encoding UTF8
     $published=$true
     Write-Host 'Retained leaver session READY. Run reviewed DC Offboard phase now; this parent remains bounded to 200 seconds.'
    }
    if($watch.Elapsed.TotalSeconds -gt 200){$process.Kill();throw 'Owned retained-session probe timed out'}
   }
   $watch.Stop()
  }elseif(-not $process.WaitForExit(60000)){$process.Kill();throw 'Owned user probe timed out'}
  if(-not(Test-Path $output)){throw 'User probe produced no result'}
  $report=Get-Content $output -Raw | ConvertFrom-Json
  if($report.RunId -ne $m.RunId -or $report.Identity -ine ('CORP\'+$subject.Name)){throw 'Invalid user evidence'}
  if($retained){
   $report | ConvertTo-Json -Depth 8 | Set-Content ('\\VBOXSVR\IAM_Evidence\leaver-session-'+$m.RunId+'-'+[Guid]::NewGuid().ToString('N')+'.json') -Encoding UTF8
   $passed=($published -and -not $report.Failure -and $report.StreamFailedUtc -and $report.FreshReadResult -in @('DENY','AUTH_REJECTED'))
   $reports+=@{Identity=$report.Identity;Passed=[bool]$passed;SessionEvidence=$report;Metric='Compare with DC DisabledUtc before claiming target; session observation alone does not establish latency.'}
  }else{
   if(@($report.Operations).Count -ne 4 -or $report.Role -ne $subject.Role -or $report.AdministrativeToken){throw 'Invalid ordinary-user operation evidence'}
   $reports+=$report
  }
 }catch{
  if($retained -and $process -and -not $process.HasExited){$process.Kill()}
  $reports+=@{Identity=('CORP\'+$subject.Name);Passed=$false;Failure=$_.Exception.Message}
 }
 finally{$credential=$null;$entry=$null}
}
$private=$null
$result=@{RunId=$m.RunId;Stage=$control.Stage;CompletedUtc=[DateTime]::UtcNow.ToString('o');Subjects=$reports;Passed=(@($reports | Where-Object {-not $_.Passed}).Count -eq 0)}
$result | ConvertTo-Json -Depth 10 | Set-Content ('\\VBOXSVR\IAM_Evidence\access-'+$control.Stage+'-'+[Guid]::NewGuid().ToString('N')+'.json') -Encoding UTF8
Write-Host ('User resource assertions complete; Passed='+$result.Passed)
