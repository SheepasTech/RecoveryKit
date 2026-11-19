<#
.SYNOPSIS
  Installs RecoveryKit (with a portable embedded Python) to a USB stick.
.DESCRIPTION
  Run this on a normal Windows PC, not in WinRE. Steps:
    1. Make sure python\python.exe exists in the project (downloads the embeddable
       Python from python.org, checks its SHA-256, rewrites the ._pth file).
    2. Copy the kit to the destination with robocopy. cases\ on the destination is
       never deleted or overwritten (customer data).
    3. Write kit-version.txt and run <dest>\run.cmd --version.
.PARAMETER Destination
  Target folder. Default D:\ITWORK\RecoveryKit. The drive must exist and the folder
  must not be the root of the system drive.
.PARAMETER RefreshPython
  Download and extract the embedded Python again even if python\python.exe exists.
.PARAMETER WhatIf
  Show what would be copied (robocopy /L), change nothing.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Destination = 'D:\ITWORK\RecoveryKit',
    [switch]$RefreshPython
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Project = $PSScriptRoot

# Embedded Python. SHA-256 pinned on first download (2026-11-19) from
# https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip
# To move to another release: change the version, run with -RefreshPython once,
# and pin the SHA-256 that is printed on mismatch (after checking it on python.org).
$PyVersion = '3.14.10'
$PyUrl     = "https://www.python.org/ftp/python/$PyVersion/python-$PyVersion-embed-amd64.zip"
$PySha256  = '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'

function Ensure-EmbeddedPython {
    $pyDir = Join-Path $Project 'python'
    $pyExe = Join-Path $pyDir 'python.exe'
    if ((Test-Path -LiteralPath $pyExe) -and -not $RefreshPython) {
        Write-Host "Embedded Python present: $pyExe"
        return
    }
    if ($WhatIfPreference) {
        Write-Host "WhatIf: would download $PyUrl into $pyDir"
        return
    }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls12'
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]'Tls13' } catch { }
    } catch { }

    New-Item -ItemType Directory -Force -Path $pyDir | Out-Null
    $zip = Join-Path $pyDir "python-$PyVersion-embed-amd64.zip"
    Write-Host "Downloading $PyUrl"
    Invoke-WebRequest -Uri $PyUrl -OutFile $zip -UseBasicParsing -UserAgent 'RecoveryKit-Install'

    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $PySha256) {
        Remove-Item -LiteralPath $zip -Force
        throw "SHA-256 mismatch for $PyUrl`n  expected $PySha256`n  got      $hash"
    }
    Write-Host "SHA-256 OK: $hash"

    # Clear old runtime files (keep .gitkeep), then extract.
    Get-ChildItem -LiteralPath $pyDir -Force |
        Where-Object { $_.FullName -ne $zip -and $_.Name -ne '.gitkeep' } |
        Remove-Item -Recurse -Force
    Expand-Archive -LiteralPath $zip -DestinationPath $pyDir -Force
    Remove-Item -LiteralPath $zip -Force

    $pth = Get-ChildItem -LiteralPath $pyDir -Filter 'python3*._pth' | Select-Object -First 1
    if (-not $pth) { throw "No python3*._pth found in $pyDir" }
    $zipName = $pth.Name -replace '\._pth$', '.zip'
    # No 'import site' line: user site-packages are ignored. '..' = kit root, '..\lib' = vendored deps.
    $lines = @($zipName, '.', '..', '..\lib')
    [IO.File]::WriteAllText($pth.FullName, (($lines -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
    Write-Host "Wrote $($pth.Name)"
}

function Invoke-Robo {
    param([string]$Src, [string]$Dst, [string[]]$Files = @(), [switch]$Purge)
    $a = @($Src, $Dst) + $Files
    if ($Files.Count -eq 0) { $a += '/E' }
    if ($Purge) { $a += '/PURGE' }
    $a += @('/FFT', '/R:2', '/W:2', '/NJH', '/NJS', '/NP', '/NDL',
            '/XD', '.git', '.project', 'debug', 'tests', 'cases', '__pycache__',
            '/XF', '*.pyc', '*.code-workspace', '.gitkeep')
    if ($WhatIfPreference) { $a += '/L' }
    & robocopy.exe @a | ForEach-Object { if ($_ -and $_.Trim()) { Write-Host "  $_" } }
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed (exit $LASTEXITCODE): $Src -> $Dst" }
}

# --- destination checks ------------------------------------------------------
$destFull = [IO.Path]::GetFullPath($Destination)
$root = [IO.Path]::GetPathRoot($destFull)          # always ends with a backslash, e.g. D:\
if (-not $root -or -not (Test-Path -LiteralPath $root)) {
    throw "Destination drive does not exist: $Destination"
}
$sysRoot = ($env:SystemDrive.TrimEnd('\') + '\')
if (($destFull -ieq $root) -and ($root -ieq $sysRoot)) {
    throw "Refusing to install into the root of the system drive ($root)."
}
if ($destFull -ieq $root) {
    throw "Destination must be a folder (for example ${root}ITWORK\RecoveryKit), not a drive root."
}
$destFull = $destFull.TrimEnd('\')
if ($destFull -ieq $Project.TrimEnd('\')) { throw 'Destination is the project folder itself.' }

# --- 1. python ---------------------------------------------------------------
Ensure-EmbeddedPython

# --- 2. copy -----------------------------------------------------------------
Write-Host "Installing to $destFull"
if (-not $WhatIfPreference) { New-Item -ItemType Directory -Force -Path $destFull | Out-Null }

Invoke-Robo $Project $destFull -Files @('run.cmd', 'README.md', 'RecoveryKit-spec.md')
foreach ($d in 'recoverykit', 'python') {
    if (Test-Path -LiteralPath (Join-Path $Project $d)) {
        Invoke-Robo (Join-Path $Project $d) (Join-Path $destFull $d) -Purge
    }
}
foreach ($d in 'lib', 'config', 'tools', 'docs') {
    if (Test-Path -LiteralPath (Join-Path $Project $d)) {
        Invoke-Robo (Join-Path $Project $d) (Join-Path $destFull $d)
    }
}

if ($WhatIfPreference) { Write-Host 'WhatIf: nothing changed.'; return }

New-Item -ItemType Directory -Force -Path (Join-Path $destFull 'cases') | Out-Null

# --- 3. version stamp --------------------------------------------------------
$hashShort = 'unknown'
try {
    $h = & git -C $Project rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $h) { $hashShort = ($h | Select-Object -First 1).Trim() }
} catch { }
$stamp = "git: $hashShort`r`ninstalled: $(Get-Date -Format 'yyyy-MM-dd HH:mm')`r`npython: $PyVersion`r`n"
[IO.File]::WriteAllText((Join-Path $destFull 'kit-version.txt'), $stamp, [Text.Encoding]::ASCII)

Write-Host ''
Write-Host "Running: $destFull\run.cmd --version"
& cmd.exe /c "`"$destFull\run.cmd`" --version"
Write-Host "run.cmd exit code: $LASTEXITCODE"
Write-Host 'Done.'
