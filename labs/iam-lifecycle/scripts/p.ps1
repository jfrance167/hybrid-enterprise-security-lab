# Copy fixture secrets directly between owned guests over encrypted admin-only SMB.
# No credentials in arguments, evidence, public source, or host transfer directories.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$computer=Get-CimInstance Win32_ComputerSystem
if($computer.Name -ne 'WS01' -or $computer.Domain -ne 'corp.example.test' -or -not $computer.PartOfDomain){throw 'Restricted to Northstar WS01.'}
$root='C:\Northstar-IAM-Client'
if(Test-Path -LiteralPath $root){throw 'Client root exists; inspect it before re-provisioning.'}
$credential=Get-Credential -UserName 'CORP\Administrator' -Message 'Northstar guest-to-guest provisioning: existing domain administrator. Do not expose this value in evidence.'
if(-not $credential){throw 'Provisioning cancelled.'}
$data=$null
try{
    $null=New-PSDrive -Name IAMProvision -PSProvider FileSystem -Root '\\DC01.corp.example.test\NorthstarIAMProvision' -Credential $credential -Scope Script
    $raw=Get-Content -LiteralPath 'IAMProvision:\credentials.json' -Raw
    $data=$raw | ConvertFrom-Json
    $expected=@('iam.sec1','iam.sec2','iam.ops1','iam.ops2','iam.mover','iam.leaver')
    if($data.SchemaVersion -ne 1 -or $data.Domain -ne 'CORP' -or $data.RunId -notmatch '^[a-f0-9]{32}$' -or @($data.Users).Count -ne 6){throw 'Invalid private fixture schema.'}
    $names=@($data.Users | ForEach-Object {$_.Name})
    if(@(Compare-Object ($expected | Sort-Object) ($names | Sort-Object)).Count){throw 'Unexpected or duplicate fixture identities.'}
    foreach($entry in $data.Users){if($entry.Password -isnot [string] -or $entry.Password.Length -lt 20 -or $entry.Password.Length -gt 128){throw 'Invalid private fixture credential boundary.'}}
    $adminSid=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    foreach($path in @($root,(Join-Path $root 'Private'))){
        $null=New-Item -Path $path -ItemType Directory
        $acl=New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($adminSid)
        foreach($sid in @($adminSid,$systemSid)){
            $null=$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
        }
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    $path=Join-Path $root 'Private\credentials.json'
    [string]$raw | Set-Content -LiteralPath $path -Encoding UTF8
    $acl=Get-Acl -LiteralPath $path
    foreach($rule in $acl.Access){
        $sid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if($sid -notin @('S-1-5-32-544','S-1-5-18')){throw 'Unexpected private-file ACL principal; stop before user tests.'}
    }
    $marker=@{SchemaVersion=1;RunId=$data.RunId;Owner='Northstar IAM synthetic client';CompletedUtc=[DateTime]::UtcNow.ToString('o');PrivateStorageVerified=$true}
    $marker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'run.json') -Encoding UTF8
    $marker | ConvertTo-Json | Set-Content -LiteralPath ('\\VBOXSVR\IAM_Evidence\client-provision-'+$data.RunId+'.json') -Encoding UTF8
    Write-Host 'Private fixture data copied to protected WS storage. Remove the owned DC provisioning share before ordinary-user tests.'
}finally{
    if(Get-PSDrive -Name IAMProvision -ErrorAction SilentlyContinue){Remove-PSDrive -Name IAMProvision -Force}
    $credential=$null;$raw=$null;$data=$null;$entry=$null
}
