# Remove only this run's temporary private provisioning share.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DC01'){throw 'DC01 only'}
$m=Get-Content 'C:\Northstar-IAM\run.json' -Raw | ConvertFrom-Json
if($m.RunId -ne '96cb9aaf65ac4de698f7cf5af0e09ca8'){throw 'Wrong run'}
$s=Get-SmbShare -Name NorthstarIAMProvision
if($s.Path -ne 'C:\Northstar-IAM\Private' -or $s.Description -ne $m.OwnerMarker -or -not $s.EncryptData){throw 'Share ownership mismatch'}
$marker=Get-Content ('\\VBOXSVR\IAM_Evidence\client-provision-'+$m.RunId+'.json') -Raw | ConvertFrom-Json
if($marker.RunId -ne $m.RunId -or -not $marker.PrivateStorageVerified){throw 'Client provisioning not verified'}
Remove-SmbShare -Name NorthstarIAMProvision -Force
if(Get-SmbShare -Name NorthstarIAMProvision -ErrorAction SilentlyContinue){throw 'Share still exists'}
@{RunId=$m.RunId;Stage='Provisioning share removed';Passed=$true;CompletedUtc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content ('\\VBOXSVR\IAM_Evidence\provision-cleanup-'+$m.RunId+'.json')
