param(
    [Parameter(Mandatory = $true)]
    [string]$VmRoot,
    [switch]$Create
)

$ErrorActionPreference = 'Stop'
$vbox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
if (-not (Test-Path -LiteralPath $vbox)) {
    throw "VirtualBox was not found at $vbox"
}

$specs = @(
    @{ Name='LAB-FW'; Os='FreeBSD_64'; Ram=4096; Cpu=2; Disk=16384; Nics=@('nat','lab-users','lab-servers','lab-mgmt') },
    @{ Name='LAB-DC01'; Os='Windows2025_64'; Ram=4096; Cpu=2; Disk=51200; Nics=@('lab-servers') },
    @{ Name='LAB-WS01'; Os='Windows11_64'; Ram=4096; Cpu=2; Disk=65536; Nics=@('lab-users') },
    @{ Name='LAB-APP01'; Os='Ubuntu_64'; Ram=2048; Cpu=2; Disk=24576; Nics=@('lab-servers') },
    @{ Name='LAB-SIEM01'; Os='Ubuntu_64'; Ram=8192; Cpu=4; Disk=61440; Nics=@('lab-mgmt') }
)

$totalRam = ($specs | Measure-Object -Property Ram -Sum).Sum
if ($totalRam -gt 32768) { throw "Guest RAM exceeds 32 GB: $totalRam MB" }

$fullRoot = [System.IO.Path]::GetFullPath($VmRoot)
if ($fullRoot -match 'OneDrive') {
    throw 'VM disks must be kept outside OneDrive.'
}
$drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($fullRoot))
if (-not $drive.IsReady -or $drive.AvailableFreeSpace -lt 100GB) {
    throw 'At least 100 GB free is required before creating the VMs.'
}

$existing = & $vbox list vms
if ($LASTEXITCODE -ne 0) { throw 'Could not list existing VirtualBox VMs.' }
foreach ($spec in $specs) {
    if ($existing -match ('^"' + [regex]::Escape($spec.Name) + '" ')) {
        throw "A VM named $($spec.Name) already exists; no changes were made."
    }
}

$specs | ForEach-Object {
    [pscustomobject]@{ Name=$_.Name; RAM_GB=$_.Ram / 1024; CPUs=$_.Cpu; Disk_GB=$_.Disk / 1024; Networks=$_.Nics -join ', ' }
} | Format-Table -AutoSize
Write-Output "Guest RAM total: $($totalRam / 1024) GB"
Write-Output "VM directory: $fullRoot"
if (-not $Create) {
    Write-Output 'Preview only. Add -Create to register the VMs.'
    return
}

function Invoke-VBox([string[]]$Arguments) {
    & $vbox @Arguments
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage failed: $($Arguments -join ' ')" }
}

New-Item -ItemType Directory -Path $fullRoot -Force | Out-Null
foreach ($spec in $specs) {
    $name = $spec.Name
    Invoke-VBox @('createvm','--name',$name,'--basefolder',$fullRoot,'--ostype',$spec.Os,'--register')
    Invoke-VBox @('modifyvm',$name,'--memory',[string]$spec.Ram,'--cpus',[string]$spec.Cpu,'--audio-enabled','off','--usb','off','--clipboard-mode','disabled','--drag-and-drop','disabled')
    if ($spec.Os -eq 'Ubuntu_64') {
        Invoke-VBox @('modifyvm',$name,'--graphicscontroller','vmsvga','--vram','32')
    } elseif ($name -eq 'LAB-WS01') {
        Invoke-VBox @('modifyvm',$name,'--graphicscontroller','vmsvga','--vram','128')
    } elseif ($spec.Os -like 'Windows*') {
        Invoke-VBox @('modifyvm',$name,'--graphicscontroller','vboxsvga','--vram','128')
    }
    if ($name -eq 'LAB-WS01') {
        Invoke-VBox @('modifyvm',$name,'--firmware','efi','--tpm-type','2.0')
    }
    for ($i = 0; $i -lt $spec.Nics.Count; $i++) {
        $slot = $i + 1
        $network = $spec.Nics[$i]
        if ($network -eq 'nat') {
            Invoke-VBox @('modifyvm',$name,"--nic$slot",'nat')
        } else {
            Invoke-VBox @('modifyvm',$name,"--nic$slot",'intnet',"--intnet$slot",$network)
        }
    }
    Invoke-VBox @('storagectl',$name,'--name','SATA','--add','sata','--controller','IntelAhci')
    $diskPath = Join-Path (Join-Path $fullRoot $name) "$name.vdi"
    Invoke-VBox @('createmedium','disk','--filename',$diskPath,'--size',[string]$spec.Disk,'--format','VDI','--variant','Standard')
    Invoke-VBox @('storageattach',$name,'--storagectl','SATA','--port','0','--device','0','--type','hdd','--medium',$diskPath)
    Write-Output "Created $name"
}
