# Online LDAP authentication proof against the owned DC; secrets remain in WS01.
# AI-assisted. Uses Microsoft .NET APIs; no third-party code or dependencies.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$run='96cb9aaf65ac4de698f7cf5af0e09ca8'
$root='C:\Northstar-IAM-Client'
$computer=Get-CimInstance Win32_ComputerSystem
if($computer.Name -ne 'WS01' -or $computer.Domain -ne 'corp.example.test' -or -not $computer.PartOfDomain){throw 'Owned WS01 domain member only.'}
$manifest=Get-Content ($root+'\run.json') -Raw | ConvertFrom-Json
if($manifest.RunId -ne $run){throw 'Fixture run mismatch.'}
$privatePath=Join-Path $root 'Private\credentials.json'
foreach($path in @((Join-Path $root 'Private'),$privatePath)){
 if((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Private path cannot be a reparse point.'}
 $acl=Get-Acl -LiteralPath $path
 if($path -ne $privatePath -and -not $acl.AreAccessRulesProtected){throw 'Private directory protection lost.'}
 foreach($rule in $acl.Access){if($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')){throw 'Unexpected private ACL principal.'}}
}
$private=Get-Content -LiteralPath $privatePath -Raw | ConvertFrom-Json
if($private.RunId -ne $run -or $private.Domain -ne 'CORP' -or $private.SchemaVersion -ne 1){throw 'Private fixture mismatch.'}
Add-Type -AssemblyName System.DirectoryServices.Protocols
if(-not ('NorthstarOnlineLogon' -as [type])){
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NorthstarOnlineLogon {
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool LogonUserW(string user, string domain, string password, int type, int provider, out IntPtr token);
 [DllImport("kernel32.dll", SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool CloseHandle(IntPtr handle);
}
'@
}
$reports=@()
foreach($name in @('iam.sec1','iam.ops2','iam.leaver','iam.sec1')){
 $entries=@($private.Users | Where-Object Name -eq $name)
 if($entries.Count -ne 1){throw 'Fixture subject mismatch.'}
 $expected=if($name -eq 'iam.sec1'){'ALLOW'}else{'AUTH_REJECTED'}
 $result=[ordered]@{Identity=('CORP\'+$name);Expected=$expected;Actual='ERROR';NetworkLogonAllowed=$false;NetworkLogonErrorCode=$null;LdapErrorCode=$null;DirectoryStatus=$null;FailureType=$null;AttemptStep='NetworkLogon';StartedUtc=[DateTime]::UtcNow.ToString('o');CompletedUtc=$null;Passed=$false}
 $connection=$null;$credential=$null
 try{
  $token=[IntPtr]::Zero
  $result.NetworkLogonAllowed=[NorthstarOnlineLogon]::LogonUserW($name,'CORP',$entries[0].Password,3,0,[ref]$token)
  if(-not $result.NetworkLogonAllowed){$result.NetworkLogonErrorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()}
  if($token -ne [IntPtr]::Zero){$null=[NorthstarOnlineLogon]::CloseHandle($token)}
  $result.AttemptStep='LdapBind'
  $identifier=New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier('DC01.corp.example.test',389,$true,$false)
  $credential=New-Object Net.NetworkCredential($name,$entries[0].Password,'CORP')
  $connection=New-Object DirectoryServices.Protocols.LdapConnection($identifier,$credential,[DirectoryServices.Protocols.AuthType]::Negotiate)
  $connection.Timeout=[TimeSpan]::FromSeconds(10)
  $connection.SessionOptions.ProtocolVersion=3
  $connection.SessionOptions.Signing=$true
  $connection.SessionOptions.Sealing=$true
  $connection.SessionOptions.ReferralChasing=[DirectoryServices.Protocols.ReferralChasingOptions]::None
  $connection.Bind()
  $result.AttemptStep='RootDseSearch'
  $request=[DirectoryServices.Protocols.SearchRequest]::new('', '(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,[string[]]@('defaultNamingContext','dnsHostName'))
  $response=$connection.SendRequest($request)
  if($response.Entries.Count -ne 1 -or $response.Entries[0].Attributes['defaultNamingContext'][0] -ine 'DC=corp,DC=example,DC=test' -or $response.Entries[0].Attributes['dnsHostName'][0] -ine 'DC01.corp.example.test'){throw 'Online DC identity mismatch.'}
  $result.Actual='ALLOW'
 }catch{
  $ex=$_.Exception;while($ex.InnerException){$ex=$ex.InnerException}
  $result.FailureType=$ex.GetType().FullName
  if($ex -is [DirectoryServices.Protocols.LdapException]){
   $result.LdapErrorCode=$ex.ErrorCode
   if($ex.ErrorCode -eq 49){$result.Actual='AUTH_REJECTED'}
   if($ex.ServerErrorMessage -match 'data ([0-9a-fA-F]+),'){$result.DirectoryStatus=$Matches[1].ToLowerInvariant()}
  }
 }finally{
  if($connection){$connection.Dispose()}
  $credential=$null;$entries=$null
  $result.CompletedUtc=[DateTime]::UtcNow.ToString('o')
  $result.Passed=($result.Actual -eq $expected -and (($expected -eq 'ALLOW' -and $result.NetworkLogonAllowed) -or ($expected -eq 'AUTH_REJECTED' -and $result.NetworkLogonErrorCode -eq 1331)))
  $reports+=@([pscustomobject]$result)
 }
}
$private=$null
$report=@{RunId=$run;Server='DC01.corp.example.test:389';Protocol='LDAPv3 SASL Negotiate with signing and sealing; new connection and explicit fixture credentials per attempt';CompletedUtc=[DateTime]::UtcNow.ToString('o');Subjects=$reports;Passed=(@($reports | Where-Object {-not $_.Passed}).Count -eq 0);Scope='Online authentication only; cached interactive/offline logon and global ticket revocation not asserted'}
$file='online-auth-'+[Guid]::NewGuid().ToString('N')+'.json'
$report | ConvertTo-Json -Depth 6 | Set-Content ('\\VBOXSVR\IAM_Evidence\'+$file) -Encoding UTF8
Clear-Host
Write-Host 'NORTHSTAR IAM | Fresh online authentication against DC01'
Write-Host ('UTC '+$report.CompletedUtc)
$reports | Format-Table Identity,Actual,NetworkLogonErrorCode,LdapErrorCode,Passed -AutoSize
Write-Host ('Aggregate Passed='+$report.Passed+' | '+$file)
if(-not $report.Passed){throw 'Online authentication evidence incomplete; inspect numeric results.'}
