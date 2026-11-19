<#
.SYNOPSIS
  Creates the ITwork local certificate authority (once) and issues a TLS server certificate with it.
.DESCRIPTION
  ADR 0020: the technician's main PC (the control host) is the certificate authority for all ITwork tools.
  - The CA (ca-cert.pem + ca-key.pem) lives in -CaDir, by default %LOCALAPPDATA%\ITwork\CA. It is created
    when missing and NEVER recreated or overwritten, also not by runs that start at the same moment: ca-key.pem is
    created with FileMode.CreateNew and that is the lock; the run that gets it makes the CA, the others wait up to
    30 s for ca-cert.pem (written last) and use that CA. The key must never be copied to a USB stick.
  - The server certificate (server-cert.pem = leaf + CA certificate, server-key.pem) goes to -OutDir. Every file is
    written as <name>.<pid>.tmp and renamed; the key is renamed before the certificate, so an interrupted run can
    leave a mismatched pair, which tlsca.py detects and issues again.
  - Key files are restricted to the current user (granted by SID, inheritance off, verified by reading the ACL
    back; SYSTEM and Administrators are not added). On a file system without ACLs (FAT, exFAT, a network share) the
    run stops, unless -AllowInsecureCaDir is given: then a WARNING line goes to the error stream.
  - Certificates are valid from 24 hours before they are issued (a target clock may be far off).
  Works in Windows PowerShell 5.1 and PowerShell 7. No administrator rights, no certificate store, no
  external tools. ECDSA P-256 is used when the runtime can do it, RSA 3072 otherwise (or with -Algorithm RSA).
.PARAMETER CaDir
  Folder of the CA. Default %LOCALAPPDATA%\ITwork\CA.
.PARAMETER OutDir
  Where server-cert.pem and server-key.pem are written. Mandatory unless -CaOnly.
.PARAMETER DnsName
  DNS names for the server certificate. Default: this computer's name and localhost.
.PARAMETER IpAddress
  IP addresses for the server certificate. Default: 127.0.0.1 and every IPv4 address of an Up, non-loopback adapter.
.PARAMETER Days
  Validity of the server certificate in days (default 397).
.PARAMETER CaOnly
  Only create the CA (or report the existing one); issue no server certificate.
.PARAMETER Force
  Issue a new server certificate even when server-cert.pem and server-key.pem already exist in -OutDir.
  Never recreates an existing CA.
.PARAMETER AllowInsecureCaDir
  Accept a CA folder or key file whose permissions cannot be restricted to the current user (warning on stderr).
.PARAMETER Algorithm
  Auto (default: ECDSA P-256, RSA 3072 when the runtime cannot do it), EC or RSA. Only used when the CA is created
  and for the server key.
#>
using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding()]
param(
    [string]$CaDir = (Join-Path $env:LOCALAPPDATA 'ITwork\CA'),
    [string]$OutDir,
    [string[]]$DnsName,
    [string[]]$IpAddress,
    [int]$Days = 397,
    [switch]$CaOnly,
    [switch]$Force,
    [ValidateSet('Auto', 'EC', 'RSA')][string]$Algorithm = 'Auto',
    [switch]$AllowInsecureCaDir
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$IsCoreRuntime = [bool]([Security.Cryptography.ECDsa].GetMethod('ExportPkcs8PrivateKey'))
$OidEc = '1.2.840.10045.2.1'
$OidRsa = '1.2.840.113549.1.1.1'

# ---------------------------------------------------------------- helpers
function ConvertTo-Pem([byte[]]$Der, [string]$Label) {
    $b64 = [Convert]::ToBase64String($Der)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("-----BEGIN $Label-----`n")
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        [void]$sb.Append($b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) + "`n")
    }
    [void]$sb.Append("-----END $Label-----`n")
    return $sb.ToString()
}

function ConvertFrom-Pem([string]$Text, [string]$Label) {
    $m = [regex]::Match($Text, "-----BEGIN $Label-----(.*?)-----END $Label-----", 'Singleline')
    if (-not $m.Success) { throw "No '$Label' block found" }
    return [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))
}

function Get-Sha256Hex([byte[]]$Bytes) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return (($h.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $h.Dispose() }
}

function Write-Warn([string]$Text) {
    # the error stream, so a caller that only looks at stderr (tlsca.py) sees it even when the exit code is 0
    [Console]::Error.WriteLine('WARNING: ' + $Text)
}

function Test-AclFileSystem([string]$Dir) {
    # $null when the folder is on a file system whose permissions can protect a key, else a short description
    $root = [IO.Path]::GetPathRoot($Dir)
    if (-not $root) { return 'no drive' }
    if ($root.StartsWith('\\')) { return 'a network share (UNC path)' }
    try { $fmt = (New-Object IO.DriveInfo($root)).DriveFormat } catch { return "an unknown file system on $root" }
    if ($fmt -ne 'NTFS' -and $fmt -ne 'ReFS') { return "a $fmt volume ($root)" }
    return $null
}

function Test-KeyAcl([string]$Path, [string]$Sid) {
    # $null when inheritance is off and only the current user has any access rule, else what is wrong.
    # Decision: SYSTEM and Administrators are NOT granted (a key that only its owner can open; an administrator can
    # still take ownership, which is the normal limit of file permissions).
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { return 'inheritance is still on' }
    foreach ($r in $acl.Access) {
        $who = $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($who -ne $Sid) { return ('access rule for ' + $r.IdentityReference.Value + ' (' + $who + ')') }
    }
    if (@($acl.Access).Count -eq 0) { return 'no access rule at all' }
    return $null
}

function Protect-KeyFile([string]$Path) {
    # current user only, granted by SID (a user name that equals the computer name can resolve to the machine SID).
    # Verified by reading the ACL back. A failure stops the run unless -AllowInsecureCaDir: then a warning on stderr.
    $problem = $null
    try {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $sid = $user.Value
        # Replace the whole access list: inheritance off and one rule, full control for the current user (by SID).
        # Removing only the inherited entries (icacls /inheritance:r) left entries behind in folders whose own
        # entries are explicit, seen with the kit's config folder.
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user, 'FullControl', 'Allow')))
        # Set through .NET, not Set-Acl: Set-Acl can demand SeSecurityPrivilege. Windows PowerShell has the method
        # on FileInfo; PowerShell 7 has it as an extension class.
        $fi = New-Object IO.FileInfo($Path)
        if ($fi | Get-Member -Name SetAccessControl -MemberType Method) { $fi.SetAccessControl($acl) }
        else { [IO.FileSystemAclExtensions]::SetAccessControl($fi, $acl) }
        $problem = Test-KeyAcl $Path $sid
    } catch {
        $problem = $_.Exception.Message
    }
    if ($problem) {
        $msg = "could not restrict the permissions of $Path to the current user: $problem"
        if ($AllowInsecureCaDir) { Write-Warn ($msg + ' (accepted because of -AllowInsecureCaDir)'); return $false }
        throw ($msg + '. Use a folder on an NTFS drive, or pass -AllowInsecureCaDir to accept this.')
    }
    return $true
}

function New-TempName([string]$Path) { return ('{0}.{1}.tmp' -f $Path, $PID) }

function Write-SecretTemp([string]$Tmp, [string]$Text) {
    # create empty, restrict, then write: the key is never readable by others, not even half written
    if (Test-Path -LiteralPath $Tmp) { Remove-Item -LiteralPath $Tmp -Force }
    [IO.File]::WriteAllBytes($Tmp, [byte[]]@())
    [void](Protect-KeyFile $Tmp)
    [IO.File]::WriteAllText($Tmp, $Text, [Text.Encoding]::ASCII)
}

function Move-IntoPlace([string]$Tmp, [string]$Dest) {
    # rename <name>.<pid>.tmp to <name>; an existing target is replaced in one step. A virus scanner or another run
    # may hold either file for a moment: try again a few times, and as the last resort delete the target and move.
    for ($i = 1; $i -le 6; $i++) {
        try {
            if (Test-Path -LiteralPath $Dest) { [IO.File]::Replace($Tmp, $Dest, [NullString]::Value) }
            else { [IO.File]::Move($Tmp, $Dest) }
            return
        } catch {
            if (-not ($_.Exception.GetBaseException() -is [IO.IOException])) { throw }
            if ($i -eq 5) {
                try { Remove-Item -LiteralPath $Dest -Force -ErrorAction Stop } catch { }
            } elseif ($i -eq 6) { throw }
            Start-Sleep -Milliseconds (100 * $i)
        }
    }
}

function Write-PlainFile([string]$Path, [string]$Text) {
    $tmp = New-TempName $Path
    try {
        [IO.File]::WriteAllText($tmp, $Text, [Text.Encoding]::ASCII)
        Move-IntoPlace $tmp $Path
    } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
}

function Write-SecretFile([string]$Path, [string]$Text) {
    $tmp = New-TempName $Path
    try {
        Write-SecretTemp $tmp $Text
        Move-IntoPlace $tmp $Path
        [void](Protect-KeyFile $Path)
    } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
}

# ---- key pairs across runtimes. Kind is 'EC' or 'RSA'. A key pair is @{Kind; Key; Pkcs8}.
function New-KeyPair([string]$Kind) {
    if ($IsCoreRuntime) {
        if ($Kind -eq 'EC') { $k = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')) }
        else { $k = [Security.Cryptography.RSA]::Create(3072) }
        return @{ Kind = $Kind; Key = $k; Pkcs8 = $k.ExportPkcs8PrivateKey() }
    }
    $p = New-Object Security.Cryptography.CngKeyCreationParameters
    $p.ExportPolicy = [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
    $p.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
    if ($Kind -eq 'EC') {
        $cng = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::ECDsaP256, [NullString]::Value, $p)
        $k = New-Object Security.Cryptography.ECDsaCng($cng)
    } else {
        $prop = New-Object Security.Cryptography.CngProperty('Length', [BitConverter]::GetBytes([int]3072), [Security.Cryptography.CngPropertyOptions]::None)
        $p.Parameters.Add($prop)
        $cng = [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa, [NullString]::Value, $p)
        $k = New-Object Security.Cryptography.RSACng($cng)
    }
    return @{ Kind = $Kind; Key = $k; Pkcs8 = $cng.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob) }
}

function Import-KeyPair([string]$Kind, [byte[]]$Der) {
    if ($IsCoreRuntime) {
        $n = 0
        if ($Kind -eq 'EC') { $k = [Security.Cryptography.ECDsa]::Create() } else { $k = [Security.Cryptography.RSA]::Create() }
        $k.ImportPkcs8PrivateKey($Der, [ref]$n)
        return @{ Kind = $Kind; Key = $k; Pkcs8 = $Der }
    }
    $cng = [Security.Cryptography.CngKey]::Import($Der, [Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
    if ($Kind -eq 'EC') { $k = New-Object Security.Cryptography.ECDsaCng($cng) } else { $k = New-Object Security.Cryptography.RSACng($cng) }
    return @{ Kind = $Kind; Key = $k; Pkcs8 = $Der }
}

function New-Request([string]$Subject, $Kp) {
    $hash = [Security.Cryptography.HashAlgorithmName]::SHA256
    if ($Kp.Kind -eq 'EC') {
        return [CertificateRequest]::new($Subject, $Kp.Key, $hash)
    }
    return [CertificateRequest]::new($Subject, $Kp.Key, $hash, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
}

function New-Generator($Kp) {
    if ($Kp.Kind -eq 'EC') { return [X509SignatureGenerator]::CreateForECDsa($Kp.Key) }
    return [X509SignatureGenerator]::CreateForRSA($Kp.Key, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
}

function New-Serial {
    $b = New-Object byte[] 16
    $r = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $r.GetBytes($b) } finally { $r.Dispose() }
    $b[0] = ($b[0] -band 0x3F) -bor 0x40        # positive, no leading zero byte
    return , $b
}

function Test-KeyKind([string]$Kind) {
    # can this runtime create the key and sign with it?
    try {
        $kp = New-KeyPair $Kind
        $imp = Import-KeyPair $Kind $kp.Pkcs8
        $req = New-Request 'CN=probe' $imp
        $nb = [DateTimeOffset]::UtcNow
        $req.Create((New-Object Security.Cryptography.X509Certificates.X500DistinguishedName('CN=probe')), (New-Generator $imp), $nb, $nb.AddDays(1), (New-Serial)) | Out-Null
        return $true
    } catch { return $false }
}

function Get-KindOfCert($Cert) {
    $o = $Cert.PublicKey.Oid.Value
    if ($o -eq $OidEc) { return 'EC' }
    if ($o -eq $OidRsa) { return 'RSA' }
    throw "Unsupported CA key type: $o"
}

function Test-ValidName([string]$s) { return ($s -match '^[A-Za-z0-9.\-]+$') -and $s.Length -le 253 }

# ---------------------------------------------------------------- main
try {
    if (-not $CaOnly -and -not $OutDir) { throw '-OutDir is required unless -CaOnly is given.' }
    if ($Days -lt 1 -or $Days -gt 825) { throw '-Days must be between 1 and 825.' }
    $computer = $env:COMPUTERNAME
    if (-not $computer) { $computer = [Net.Dns]::GetHostName() }
    $runtime = if ($IsCoreRuntime) { 'PowerShell ' + $PSVersionTable.PSVersion + ' (.NET Core)' } else { 'Windows PowerShell ' + $PSVersionTable.PSVersion + ' (.NET Framework)' }
    Write-Host "Runtime: $runtime"

    $CaDir = [IO.Path]::GetFullPath($CaDir)
    $caCertPath = Join-Path $CaDir 'ca-cert.pem'
    $caKeyPath = Join-Path $CaDir 'ca-key.pem'

    $kind = $Algorithm
    if ($kind -eq 'Auto') { $kind = if (Test-KeyKind 'EC') { 'EC' } else { 'RSA' } }
    elseif ($kind -eq 'EC' -and -not (Test-KeyKind 'EC')) { throw 'This runtime cannot do ECDSA P-256.' }
    if ($Algorithm -eq 'Auto' -and $kind -eq 'RSA') { Write-Host 'ECDSA is not usable on this runtime: using RSA 3072.' }

    # ---- CA
    $aclProblem = Test-AclFileSystem $CaDir
    if ($aclProblem) {
        $m = "The CA folder $CaDir is on $aclProblem, where file permissions cannot keep ca-key.pem private."
        if ($AllowInsecureCaDir) { Write-Warn ($m + ' (accepted because of -AllowInsecureCaDir)') }
        else { throw ($m + ' Use -CaDir on an NTFS drive, or pass -AllowInsecureCaDir to accept this.') }
    }
    $haveCert = Test-Path -LiteralPath $caCertPath
    $haveKey = Test-Path -LiteralPath $caKeyPath
    if ($haveCert -and -not $haveKey) {
        throw "Half a CA in ${CaDir}: ca-cert.pem exists but ca-key.pem is missing. Not touching it: delete ca-cert.pem there (a new CA is then created and every stick needs Install-ToUsb.ps1 again), or restore ca-key.pem."
    }
    $nowUtc = [DateTimeOffset]::UtcNow
    $skew = $nowUtc.AddHours(-24)      # WinRE clocks are often wrong: certificates start a day in the past
    $createCa = $false
    if (-not $haveCert) {
        New-Item -ItemType Directory -Force -Path $CaDir | Out-Null
        # ca-key.pem created with CreateNew is the lock: exactly one run gets it
        try {
            $lock = [IO.File]::Open($caKeyPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $lock.Dispose()
            $createCa = $true
        } catch {
            if (-not ($_.Exception.GetBaseException() -is [IO.IOException])) { throw }
            $limit = (Get-Date).AddSeconds(30)
            while (-not (Test-Path -LiteralPath $caCertPath) -and (Get-Date) -lt $limit) { Start-Sleep -Milliseconds 200 }
            if (-not (Test-Path -LiteralPath $caCertPath)) {
                throw "Half a CA in ${CaDir}: ca-key.pem exists but ca-cert.pem did not appear within 30 s (another run may have failed half way). Not touching it: delete ca-key.pem there and run again."
            }
            Write-Host 'Another run created the CA at the same moment: using it.'
        }
    }
    if (-not $createCa) {
        $caDer = ConvertFrom-Pem ([IO.File]::ReadAllText($caCertPath)) 'CERTIFICATE'
        $caCert = [X509Certificate2]::new([byte[]]$caDer)
        $caKind = Get-KindOfCert $caCert
        $caKp = Import-KeyPair $caKind (ConvertFrom-Pem ([IO.File]::ReadAllText($caKeyPath)) 'PRIVATE KEY')
        if ($caCert.NotAfter -lt (Get-Date)) { throw "The CA certificate expired on $($caCert.NotAfter). Create a new CA (move the CA folder away) and run Install-ToUsb.ps1 for every stick." }
        Write-Host "CA reused: $caCertPath"
    } else {
      try {
        $caKp = New-KeyPair $kind
        $caKind = $kind
        $subject = "CN=ITwork Local CA ($computer), O=ITwork"
        $req = New-Request $subject $caKp
        $req.CertificateExtensions.Add(([X509BasicConstraintsExtension]::new($true, $true, 0, $true)))
        $req.CertificateExtensions.Add(([X509KeyUsageExtension]::new([X509KeyUsageFlags]'KeyCertSign, CrlSign', $true)))
        $req.CertificateExtensions.Add(([X509SubjectKeyIdentifierExtension]::new($req.PublicKey, $false)))
        $name = [X500DistinguishedName]::new($subject)
        $caCert = $req.Create($name, (New-Generator $caKp), $skew, $nowUtc.AddYears(10), (New-Serial))
        $certPem = ConvertTo-Pem $caCert.RawData 'CERTIFICATE'
        $keyPem = ConvertTo-Pem $caKp.Pkcs8 'PRIVATE KEY'
        # ca-key.pem is the empty lock file made above: it is filled in place (nobody reads it before ca-cert.pem
        # exists), after its permissions are restricted. ca-cert.pem is renamed into place LAST.
        [void](Protect-KeyFile $caKeyPath)
        [IO.File]::WriteAllText($caKeyPath, $keyPem, [Text.Encoding]::ASCII)
        $readme = @"
ITwork local certificate authority (ADR 0020)

This folder belongs to the technician's main PC (the control host). It holds the private CA that signs the TLS
certificates of the ITwork tools (RecoveryKit control server and others).

  ca-cert.pem   The CA certificate. Public. Copy THIS file to USB sticks (Install-ToUsb.ps1 does it).
  ca-key.pem    The CA PRIVATE KEY. Anyone who has it can impersonate the server.
                NEVER copy it to a USB stick, a share, a ticket or a backup you do not control.
  issued.log    One line per server certificate issued.

If this folder is lost: a new CA is created on the next run and every stick needs Install-ToUsb.ps1 again.
Created by New-ItworkCertificates.ps1 on $computer, $((Get-Date).ToString('yyyy-MM-dd HH:mm')).
"@
        Write-PlainFile (Join-Path $CaDir 'README.txt') ($readme -replace "`r?`n", "`r`n")
        Write-PlainFile $caCertPath $certPem
        Write-Host "CA created: $caCertPath ($caKind)"
      } catch {
        if (-not (Test-Path -LiteralPath $caCertPath)) { Remove-Item -LiteralPath $caKeyPath -Force -ErrorAction SilentlyContinue }
        throw
      }
    }
    $caFp = Get-Sha256Hex $caCert.RawData
    Write-Host "CA subject:     $($caCert.Subject)"
    Write-Host "CA SHA-256:     $caFp"
    Write-Host "CA expires:     $($caCert.NotAfter.ToString('yyyy-MM-dd'))"

    if ($CaOnly) { Write-Host 'Done (CA only).'; exit 0 }

    # ---- server certificate
    $OutDir = [IO.Path]::GetFullPath($OutDir)
    $certOut = Join-Path $OutDir 'server-cert.pem'
    $keyOut = Join-Path $OutDir 'server-key.pem'
    if ((Test-Path -LiteralPath $certOut) -and (Test-Path -LiteralPath $keyOut) -and -not $Force) {
        Write-Host "A server certificate already exists in $OutDir. Use -Force to issue a new one."
        exit 0
    }
    # with -File a comma list arrives as one string: split it
    $DnsName = @($DnsName | ForEach-Object { $_ -split ',' } | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
    $IpAddress = @($IpAddress | ForEach-Object { $_ -split ',' } | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
    if (-not $DnsName -or $DnsName.Count -eq 0) { $DnsName = @($computer, 'localhost') }
    if (-not $IpAddress -or $IpAddress.Count -eq 0) {
        $ips = New-Object System.Collections.Generic.List[string]
        $ips.Add('127.0.0.1')
        foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -eq 'Loopback') { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq 'InterNetwork' -and -not $ips.Contains($ua.Address.ToString())) { $ips.Add($ua.Address.ToString()) }
            }
        }
        $IpAddress = $ips.ToArray()
    }
    $dns = @(); foreach ($d in $DnsName) { if (-not (Test-ValidName $d)) { throw "Not a valid DNS name: '$d'" }; if ($dns -notcontains $d) { $dns += $d } }
    $ipObjs = @(); foreach ($i in $IpAddress) {
        $o = $null
        if (-not [Net.IPAddress]::TryParse($i, [ref]$o) -or $o.ToString() -ne $i) { throw "Not an IP address in its usual written form: '$i' (for example 192.168.1.10)" }
        if ($ipObjs -notcontains $o) { $ipObjs += $o }
    }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    $leafKind = if ($Algorithm -eq 'RSA') { 'RSA' } elseif ($Algorithm -eq 'EC') { 'EC' } else { $kind }
    $leafKp = New-KeyPair $leafKind
    $subject = "CN=$($dns[0])"
    $req = New-Request $subject $leafKp
    $san = [SubjectAlternativeNameBuilder]::new()
    foreach ($d in $dns) { $san.AddDnsName($d) }
    foreach ($o in $ipObjs) { $san.AddIpAddress($o) }
    $req.CertificateExtensions.Add($san.Build($false))
    $req.CertificateExtensions.Add(([X509BasicConstraintsExtension]::new($false, $false, 0, $true)))
    $flags = 'DigitalSignature'
    if ($leafKind -eq 'RSA') { $flags = 'DigitalSignature, KeyEncipherment' }
    $req.CertificateExtensions.Add(([X509KeyUsageExtension]::new([X509KeyUsageFlags]$flags, $true)))
    $oids = New-Object Security.Cryptography.OidCollection
    [void]$oids.Add((New-Object Security.Cryptography.Oid('1.3.6.1.5.5.7.3.1', 'Server Authentication')))
    $req.CertificateExtensions.Add(([X509EnhancedKeyUsageExtension]::new($oids, $false)))
    $req.CertificateExtensions.Add(([X509SubjectKeyIdentifierExtension]::new($req.PublicKey, $false)))
    # AuthorityKeyIdentifier = SEQUENCE { [0] keyIdentifier } with the CA's subject key identifier
    $skiExt = $caCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' } | Select-Object -First 1
    if ($skiExt) {
        $hex = $skiExt.SubjectKeyIdentifier
        $kid = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $kid.Length; $i++) { $kid[$i] = [Convert]::ToByte($hex.Substring(2 * $i, 2), 16) }
        $aki = [byte[]](@(0x30, ($kid.Length + 2), 0x80, $kid.Length) + $kid)
        $req.CertificateExtensions.Add(([X509Extension]::new((New-Object Security.Cryptography.Oid('2.5.29.35')), $aki, $false)))
    }
    $serial = New-Serial
    $notAfter = $nowUtc.AddDays($Days)
    if ($notAfter -gt $caCert.NotAfter) { $notAfter = [DateTimeOffset]$caCert.NotAfter }
    $leaf = $req.Create($caCert.SubjectName, (New-Generator $caKp), $skew, $notAfter, $serial)

    # both as .tmp first, then the key is renamed, then the certificate (tlsca.py issues again when they ever mismatch)
    $keyTmp, $certTmp = (New-TempName $keyOut), (New-TempName $certOut)
    try {
        Write-SecretTemp $keyTmp (ConvertTo-Pem $leafKp.Pkcs8 'PRIVATE KEY')
        [IO.File]::WriteAllText($certTmp, ((ConvertTo-Pem $leaf.RawData 'CERTIFICATE') + (ConvertTo-Pem $caCert.RawData 'CERTIFICATE')), [Text.Encoding]::ASCII)
        Move-IntoPlace $keyTmp $keyOut
        Move-IntoPlace $certTmp $certOut
        [void](Protect-KeyFile $keyOut)
    } finally {
        foreach ($t in $keyTmp, $certTmp) { if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue } }
    }

    $sans = (@($dns | ForEach-Object { "DNS:$_" }) + @($ipObjs | ForEach-Object { "IP:$_" })) -join ', '
    $serialHex = (($serial | ForEach-Object { $_.ToString('x2') }) -join '')
    $line = '{0} serial={1} subject={2} san=[{3}] notAfter={4}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $serialHex, $subject, $sans, $leaf.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')
    # parallel runs append to the same log: one at a time (a named mutex), so no line is lost
    $logPath = Join-Path $CaDir 'issued.log'
    $mutex = New-Object Threading.Mutex($false, ('Local\ITworkCertLog-' + (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($logPath.ToLowerInvariant()))).Substring(0, 24)))
    $held = $false
    try {
        try { $held = $mutex.WaitOne(15000) } catch [Threading.AbandonedMutexException] { $held = $true }
        for ($try = 1; $try -le 8; $try++) {
            try { Add-Content -LiteralPath $logPath -Value $line -Encoding ASCII; break }
            catch { if ($try -eq 8) { Write-Warn "could not append to issued.log: $($_.Exception.Message)" } else { Start-Sleep -Milliseconds (50 * $try) } }
        }
    } finally { if ($held) { $mutex.ReleaseMutex() }; $mutex.Dispose() }

    Write-Host "Server certificate written: $certOut"
    Write-Host "Server key written:         $keyOut"
    Write-Host "Server cert SHA-256: $(Get-Sha256Hex $leaf.RawData)"
    Write-Host "Server cert SANs:    $sans"
    Write-Host "Server cert expires: $($leaf.NotAfter.ToString('yyyy-MM-dd HH:mm')) (key type $leafKind)"
    Write-Host 'Done.'
    exit 0
} catch {
    [Console]::Error.WriteLine("ERROR: " + $_.Exception.Message)
    exit 1
}
