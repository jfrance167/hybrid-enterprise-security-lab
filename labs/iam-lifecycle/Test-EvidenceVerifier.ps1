# Negative checks use private temporary copies and never change committed evidence.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$verifier=Join-Path $PSScriptRoot 'Verify-Evidence.ps1'
$baseline=Join-Path $PSScriptRoot 'evidence'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('northstar-verifier-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -Path $temp -ItemType Directory
$cases=@(
 @{Name='Duplicate admin groups accepted';Key='directory';Change={param($r)$r.PrivilegedGroupSids=@($r.PrivilegedGroupSids[0])*8}},
 @{Name='Directory admin status ignored';Key='directory';Change={param($r)$r.Users[0].Admin=$true}},
 @{Name='Directory enabled state ignored';Key='directory';Change={param($r)($r.Users | Where-Object User -eq 'iam.leaver').Enabled=$true}},
 @{Name='Directory subject omitted';Key='directory';Change={param($r)$r.Users=@($r.Users | Select-Object -First 5)}},
 @{Name='Missing operation';Key='final';Change={param($r)$r.Subjects[0].Operations=@($r.Subjects[0].Operations | Select-Object -First 3)}},
 @{Name='Wrong role accepted';Key='mover';Change={param($r)$r.Subjects[0].Role='SystemsOperator'}},
 @{Name='Admin process accepted';Key='joiner';Change={param($r)$r.Subjects[0].AdministrativeToken=$true}},
 @{Name='Network error called denial';Key='final';Change={param($r)($r.Subjects[0].Operations | Where-Object Actual -eq 'DENY' | Select-Object -First 1).ErrorCode=-2147024894}},
 @{Name='Seeded findings hidden';Key='seeded';Change={param($r)$r.Passed=$true}},
 @{Name='Authentication unrelated reason';Key='onlineAuth';Change={param($r)$r.Subjects[1].NetworkLogonErrorCode=1326}},
 @{Name='Healthy auth control failure';Key='onlineAuth';Change={param($r)$r.Subjects[0].NetworkLogonAllowed=$false}},
 @{Name='Old final proof reused';Key='final';Change={param($r)$r.CompletedUtc='2026-10-13T03:00:00Z'}},
 @{Name='Recovery target missed';Key='recovered';Change={param($r)$r.CompletedUtc='2026-10-13T03:05:00Z'}},
 @{Name='Held revocation target missed';Key='session';Change={param($r)$r.StreamFailedUtc='2026-10-13T03:15:00Z'}},
 @{Name='Fresh read stayed allowed';Key='session';Change={param($r)$r.FreshReadResult='ALLOW'}},
 @{Name='Disabled role retained';Key='phaseOffboardRetest';Change={param($r)($r.After.Users | Where-Object Name -eq 'iam.leaver').DirectGroups=@('CN=IAM-SystemsOperator,OU=IAM-Lifecycle-Lab,OU=Lab,DC=corp,DC=example,DC=test')}}
)
try{
 $result=& $verifier -EvidenceDirectory $baseline
 if(-not $result.Passed -or [Math]::Abs($result.ActualAccessRecoverySeconds-43.1353517) -gt 0.000001 -or [Math]::Abs($result.HeldStreamRevocationSeconds-4.7467754) -gt 0.000001 -or [Math]::Abs($result.FreshReadDenialSeconds-4.7715771) -gt 0.000001){throw 'Baseline metrics failed'}
 $outcomes=@()
 foreach($case in $cases){
  $directory=Join-Path $temp ([Guid]::NewGuid().ToString('N'))
  $null=New-Item -Path $directory -ItemType Directory
  Copy-Item -Path (Join-Path $baseline '*.json') -Destination $directory
  $index=Get-Content (Join-Path $directory 'index.json') -Raw | ConvertFrom-Json
  $path=Join-Path $directory $index.($case.Key)
  $report=Get-Content $path -Raw | ConvertFrom-Json
  & $case.Change $report
  $report | ConvertTo-Json -Depth 20 | Set-Content $path -Encoding UTF8
  $rejected=$false
  try{$null=& $verifier -EvidenceDirectory $directory}catch{$rejected=$true}
  if(-not $rejected){throw ('Verifier accepted: '+$case.Name)}
  $outcomes+=@{Name=$case.Name;Rejected=$true}
 }
 [pscustomobject]@{Passed=$true;Baseline=$result;NegativeChecks=$outcomes}
}finally{
 # Delete only the unique directory created here after confirming its boundary.
 $resolved=[IO.Path]::GetFullPath($temp)
 $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
 if(-not $resolved.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^northstar-verifier-[a-f0-9]{32}$'){throw 'Temporary cleanup boundary mismatch'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
