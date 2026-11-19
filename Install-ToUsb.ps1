<#
.SYNOPSIS
  Installs RecoveryKit (with a portable embedded Python) to a USB stick.
.DESCRIPTION
  Run this on a normal Windows PC, not in WinRE. Steps:
    1. Make sure python\python.exe exists in the project (downloads the embeddable
       Python from python.org, checks its SHA-256, rewrites the ._pth file).
    2. Copy the kit to the destination with robocopy. cases\ on the destination is
       never deleted or overwritten (customer data).
    3. Copy the CA certificate of this PC (ADR 0020) to <dest>\config\ca-cert.pem, creating the CA first when
       there is none. Only the certificate: never ca-key.pem, server-key.pem or token files. The install fails
       if one of those exists under the destination.
    4. Write kit-version.txt and run <dest>\run.cmd --version.
.PARAMETER Destination
  Target folder. Default D:\ITWORK\RecoveryKit. The drive must exist and the folder
  must not be the root of the system drive.
.PARAMETER RefreshPython
  Download and extract the embedded Python again even if python\python.exe exists.
.PARAMETER CaDir
  Folder of this PC's certificate authority. Default %LOCALAPPDATA%\ITwork\CA.
.PARAMETER WhatIf
  Show what would be copied (robocopy /L), change nothing.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Destination = 'D:\ITWORK\RecoveryKit',
    [switch]$RefreshPython,
    [string]$CaDir = (Join-Path $env:LOCALAPPDATA 'ITwork\CA')
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
        Test-EmbeddedPython $pyDir $pyExe
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
    Write-PthFile $pth
}

# The ._pth file: exactly these four lines. No 'import site' line: user site-packages are ignored.
# '..' = kit root, '..\lib' = vendored deps.
function Get-ExpectedPth {
    param($Pth)
    return @(($Pth.Name -replace '\._pth$', '.zip'), '.', '..', '..\lib')
}

function Write-PthFile {
    param($Pth)
    $lines = Get-ExpectedPth $Pth
    [IO.File]::WriteAllText($Pth.FullName, (($lines -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
    Write-Host "Wrote $($Pth.Name)"
}

# An interpreter that is already in the project is not trusted blindly: its DLL and ._pth must be there and the
# ._pth must be the expected one (a changed ._pth could make it load code from elsewhere).
function Test-EmbeddedPython {
    param([string]$PyDir, [string]$PyExe)
    $dll = @(Get-ChildItem -LiteralPath $PyDir -Filter 'python3*.dll' -ErrorAction SilentlyContinue)
    if ($dll.Count -eq 0) { throw "python\python3*.dll is missing in $PyDir. Run with -RefreshPython." }
    $pth = Get-ChildItem -LiteralPath $PyDir -Filter 'python3*._pth' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pth) { throw "python\python3*._pth is missing in $PyDir. Run with -RefreshPython." }
    $want = Get-ExpectedPth $pth
    $have = @([IO.File]::ReadAllText($pth.FullName) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ((($have -join '|') -ne ($want -join '|')) -or ($have.Count -ne $want.Count)) {
        Write-Host "WARNING: $($pth.Name) is not the expected four lines ($($want -join ', ')); rewriting it."
        if (-not $WhatIfPreference) { Write-PthFile $pth }
    }
    $ver = & $PyExe --version 2>&1 | Select-Object -First 1
    Write-Host "Interpreter: $ver"
}

function Invoke-Robo {
    param([string]$Src, [string]$Dst, [string[]]$Files = @(), [switch]$Purge)
    $a = @($Src, $Dst) + $Files
    if ($Files.Count -eq 0) { $a += '/E' }
    if ($Purge) { $a += '/PURGE' }
    $a += @('/FFT', '/R:2', '/W:2', '/NJH', '/NJS', '/NP', '/NDL',
            '/XD', '.git', '.project', 'debug', 'tests', 'cases', 'devices', '__pycache__',
            '/XF', '*.pyc', '*.code-workspace', '.gitkeep', 'token*', 'server-key.pem', 'ca-key.pem', 'server-cert.pem', 'ca-cert.pem', '.mcp.json',
            '*.secret', '.env', '.env.*', '*.key')
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

# /PURGE deletes whatever is in the destination's recoverykit and python folders that the source lacks: only do that
# when the destination is new or empty, or already a kit (run.cmd and kit-version.txt both present).
$allowPurge, $purgeNote = $true, ''
if (Test-Path -LiteralPath $destFull) {
    $existing = @(Get-ChildItem -LiteralPath $destFull -Force -ErrorAction SilentlyContinue)
    $hasRun = Test-Path -LiteralPath (Join-Path $destFull 'run.cmd')
    $hasVer = Test-Path -LiteralPath (Join-Path $destFull 'kit-version.txt')
    if ($existing.Count -gt 0 -and -not ($hasRun -and $hasVer)) {
        $allowPurge = $false
        $purgeNote = "$destFull has files but is not a RecoveryKit (run.cmd and kit-version.txt are not both there)"
    }
}

# --- 1. python ---------------------------------------------------------------
Ensure-EmbeddedPython

# --- 2. copy -----------------------------------------------------------------
Write-Host "Installing to $destFull"
if (-not $WhatIfPreference) { New-Item -ItemType Directory -Force -Path $destFull | Out-Null }

Invoke-Robo $Project $destFull -Files @('run.cmd', 'README.md', 'RecoveryKit-spec.md')
if (-not $allowPurge) {
    Write-Host "WARNING: copying without /PURGE: $purgeNote. Files of an older version stay where they are."
}
foreach ($d in 'recoverykit', 'python') {
    if (Test-Path -LiteralPath (Join-Path $Project $d)) {
        Invoke-Robo (Join-Path $Project $d) (Join-Path $destFull $d) -Purge:$allowPurge
    }
}
foreach ($d in 'lib', 'config', 'tools', 'docs', 'plugins') {
    if (Test-Path -LiteralPath (Join-Path $Project $d)) {
        Invoke-Robo (Join-Path $Project $d) (Join-Path $destFull $d)
    }
}

if ($WhatIfPreference) { Write-Host 'WhatIf: nothing changed.'; return }

New-Item -ItemType Directory -Force -Path (Join-Path $destFull 'cases') | Out-Null

# --- 3. CA certificate (public part only) --------------------------------------
$caCertSrc = Join-Path $CaDir 'ca-cert.pem'
if (-not (Test-Path -LiteralPath $caCertSrc)) {
    Write-Host "No CA yet in ${CaDir}: creating it."
    $certScript = Join-Path $Project 'New-ItworkCertificates.ps1'
    $psExe = (Get-Process -Id $PID).Path
    & $psExe -NoProfile -ExecutionPolicy Bypass -File $certScript -CaDir $CaDir -CaOnly
    if ($LASTEXITCODE -ne 0) { throw "New-ItworkCertificates.ps1 -CaOnly failed (exit $LASTEXITCODE)" }
}
if (-not (Test-Path -LiteralPath $caCertSrc)) { throw "No CA certificate at $caCertSrc" }
$cfgDest = Join-Path $destFull 'config'
New-Item -ItemType Directory -Force -Path $cfgDest | Out-Null
Copy-Item -LiteralPath $caCertSrc -Destination (Join-Path $cfgDest 'ca-cert.pem') -Force
$caFp = (Get-FileHash -LiteralPath (Join-Path $cfgDest 'ca-cert.pem') -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "CA certificate copied to $cfgDest\ca-cert.pem (file SHA-256 $caFp)"

# Final check: no private key and no token file may be on the stick.
$secretFiles = @(Get-ChildItem -LiteralPath $destFull -Recurse -Force -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in 'ca-key.pem', 'server-key.pem', 'token-server.json' })
if ($secretFiles.Count -gt 0) {
    throw ("Secret files found on the stick, remove them: " + (($secretFiles | ForEach-Object { $_.FullName }) -join '; '))
}

# --- 4. version stamp --------------------------------------------------------
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
