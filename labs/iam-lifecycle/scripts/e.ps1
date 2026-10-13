# Ordinary-user resource probe. No credentials are accepted in arguments.
param([ValidatePattern('^iam\.(sec[12]|ops[12]|mover|leaver)$')][string]$Name,[ValidateSet('SecurityReader','SystemsOperator')][string]$Role,[ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,[string]$ResultPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$actual=$identity.Name
$isAdmin=@($identity.Groups | ForEach-Object {$_.Value}) -contains 'S-1-5-32-544'
if($actual -ine ('CORP\'+$Name) -or $isAdmin){throw 'Incorrect ordinary-user context'}
$records=@()
foreach($resource in @('Review','Ops')){
 foreach($operation in @('Read','Write')){
  $expected=if(($Role -eq 'SecurityReader' -and $resource -eq 'Review' -and $operation -eq 'Read') -or ($Role -eq 'SystemsOperator' -and $resource -eq 'Ops')){'ALLOW'}else{'DENY'}
  $base='\\DC01.corp.example.test\NorthstarIAM'+$resource
  $result='ERROR';$code=$null
  try{
   if($operation -eq 'Read'){
    $content=[IO.File]::ReadAllText($base+'\baseline.txt')
    if(-not $content.Contains($RunId)){throw 'Wrong resource content'}
   }else{
    $path=$base+'\probe-'+$Name+'-'+[Guid]::NewGuid().ToString('N')+'.txt'
    [IO.File]::WriteAllText($path,'Synthetic IAM probe '+$RunId)
   }
   $result='ALLOW'
  }catch{
   $ex=$_.Exception
   while($ex.InnerException){$ex=$ex.InnerException}
   $code=$ex.HResult
   if($ex -is [UnauthorizedAccessException] -or (($code -band 65535) -eq 5)){$result='DENY'}
  }
  $records+=@{Resource=$resource;Operation=$operation;Expected=$expected;Actual=$result;Passed=($result -eq $expected);ErrorCode=$code}
 }
}
@{RunId=$RunId;Identity=$actual;AdministrativeToken=$isAdmin;Role=$Role;CompletedUtc=[DateTime]::UtcNow.ToString('o');Operations=$records;Passed=(@($records | Where-Object {-not $_.Passed}).Count -eq 0)} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
