# Retained ordinary-user SMB stream probe; no passwords or ticket purging.
param([ValidateSet('iam.leaver')][string]$Name,[ValidateSet('SystemsOperator')][string]$Role,[ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,[string]$ResultPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($identity.Name -ine 'CORP\iam.leaver' -or @($identity.Groups | ForEach-Object {$_.Value}) -contains 'S-1-5-32-544'){throw 'Ordinary fictional leaver context required.'}
$base='\\DC01.corp.example.test\NorthstarIAMOps'
$started=[DateTime]::UtcNow
$report=[ordered]@{RunId=$RunId;Identity=$identity.Name;AdministrativeToken=$false;StartedUtc=$started.ToString('o');ReadyUtc=$null;StreamFailedUtc=$null;StreamErrorCode=$null;CleanupErrorCode=$null;FreshReadResult='NOT RUN';FreshReadUtc=$null;FreshReadErrorCode=$null;CompletedUtc=$null;Failure=$null;Scope='Targeted SMB resource/session only; global Kerberos revocation not asserted'}
$stream=$null
try{
 if(-not ([IO.File]::ReadAllText($base+'\baseline.txt')).Contains($RunId)){throw 'Wrong resource content.'}
 $path=$base+'\session-iam.leaver-'+[Guid]::NewGuid().ToString('N')+'.txt'
 $stream=New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
 $bytes=[Text.Encoding]::UTF8.GetBytes('Synthetic retained-session probe '+$RunId+"`r`n")
 $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
 $report.ReadyUtc=[DateTime]::UtcNow.ToString('o')
 @{RunId=$RunId;Identity=$identity.Name;Ready=$true;ReadyUtc=$report.ReadyUtc;InitialReadWriteVerified=$true} | ConvertTo-Json | Set-Content -LiteralPath ($ResultPath+'.ready.tmp') -Encoding UTF8
 Move-Item -LiteralPath ($ResultPath+'.ready.tmp') -Destination ($ResultPath+'.ready.json')
 while(([DateTime]::UtcNow-$started).TotalSeconds -lt 180){
  Start-Sleep -Milliseconds 1000
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}catch{
   $ex=$_.Exception;while($ex.InnerException){$ex=$ex.InnerException}
   $report.StreamFailedUtc=[DateTime]::UtcNow.ToString('o');$report.StreamErrorCode=$ex.HResult
   break
  }
 }
 if(-not $report.StreamFailedUtc){throw 'No held-stream failure observed within 180 seconds.'}
 # A forcibly closed SMB handle may throw during Dispose. Preserve that code,
 # release the reference, and still attempt the independent fresh resource read.
 try{$stream.Dispose()}catch{
  $ex=$_.Exception;while($ex.InnerException){$ex=$ex.InnerException}
  $report.CleanupErrorCode=$ex.HResult
 }finally{$stream=$null}
 while(([DateTime]::UtcNow-$started).TotalSeconds -lt 190){
  $fresh='ERROR';$code=$null
  try{
   $content=[IO.File]::ReadAllText($base+'\baseline.txt')
   if(-not $content.Contains($RunId)){throw 'Wrong resource content.'}
   $fresh='ALLOW'
  }catch{
   $ex=$_.Exception;while($ex.InnerException){$ex=$ex.InnerException};$code=$ex.HResult
   if(($code -band 65535) -eq 5){$fresh='DENY'}
   elseif(($code -band 65535) -in @(1326,1330,1331,1909)){$fresh='AUTH_REJECTED'}
  }
  $report.FreshReadResult=$fresh;$report.FreshReadErrorCode=$code;$report.FreshReadUtc=[DateTime]::UtcNow.ToString('o')
  if($fresh -in @('DENY','AUTH_REJECTED')){break}
  Start-Sleep -Milliseconds 1000
 }
 if($report.FreshReadResult -notin @('DENY','AUTH_REJECTED')){throw 'Fresh read remained allowed or failed for an unrelated reason.'}
}catch{$report.Failure=$_.Exception.Message}
finally{
 if($stream){try{$stream.Dispose()}catch{if(-not $report.Failure){$report.Failure='Held stream cleanup failed; inspect retained-session evidence.'}}}
 $report.CompletedUtc=[DateTime]::UtcNow.ToString('o')
 $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}
