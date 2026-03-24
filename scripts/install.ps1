<#
.SYNOPSIS
    StealthOS Relay Server installer for Windows.

.DESCRIPTION
    Downloads, verifies, and installs the StealthOS Relay Server as a Windows
    Service. Pre-built binaries are fetched from GitHub Releases with SHA256
    checksum verification.

.PARAMETER Version
    Specific version to install (e.g., "v0.1.0"). Defaults to "latest".

.PARAMETER Uninstall
    Remove StealthRelay completely.

.PARAMETER Update
    Update the binary while preserving keys and configuration.

.PARAMETER NoService
    Don't register a Windows Service.

.PARAMETER NoBrowser
    Don't auto-open the browser after installation.

.EXAMPLE
    # Install latest version
    .\install.ps1

    # Install specific version
    .\install.ps1 -Version v0.1.0

    # Update to latest
    .\install.ps1 -Update

    # Uninstall
    .\install.ps1 -Uninstall
#>

param(
    [string]$Version = "latest",
    [switch]$Uninstall,
    [switch]$Update,
    [switch]$NoService,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────────────────────

$Repo = "Olib-AI/StealthRelay"
$ServiceName = "StealthRelay"
$ServiceDisplayName = "StealthOS Relay Server"
$InstallDir = Join-Path $env:ProgramFiles "StealthRelay"
$DataDir = Join-Path $env:ProgramData "StealthRelay"
$KeyDir = Join-Path $DataDir "keys"
$ConfigPath = Join-Path $DataDir "config.toml"
$BinaryPath = Join-Path $InstallDir "stealth-relay.exe"
$LogPath = Join-Path $DataDir "stealth-relay.log"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Info    { param($Msg) Write-Host "[info]  $Msg" -ForegroundColor Cyan }
function Write-Success { param($Msg) Write-Host "[ok]    $Msg" -ForegroundColor Green }
function Write-Warn    { param($Msg) Write-Host "[warn]  $Msg" -ForegroundColor Yellow }
function Write-Fatal   { param($Msg) Write-Host "[error] $Msg" -ForegroundColor Red; exit 1 }

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── Platform detection ────────────────────────────────────────────────────────

function Get-Architecture {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
        return "arm64"
    }
    return "amd64"
}

# ── Version resolution ────────────────────────────────────────────────────────

function Resolve-Version {
    if ($Version -eq "latest") {
        Write-Info "Fetching latest release version..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
            $script:Version = $release.tag_name
        }
        catch {
            Write-Fatal "Failed to fetch latest version: $_"
        }
    }
    Write-Success "Version: $Version"
}

# ── Download and verify ──────────────────────────────────────────────────────

function Download-Binary {
    $arch = Get-Architecture
    $artifact = "stealth-relay-windows-${arch}.exe"
    $baseUrl = "https://github.com/$Repo/releases/download/$Version"
    $tmpDir = Join-Path $env:TEMP "stealth-relay-install"

    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    Write-Info "Downloading $artifact..."
    try {
        Invoke-WebRequest -Uri "$baseUrl/$artifact" -OutFile (Join-Path $tmpDir $artifact)
    }
    catch {
        Write-Fatal "Failed to download binary. Check that version $Version exists."
    }

    Write-Info "Downloading checksums..."
    try {
        Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS.txt" -OutFile (Join-Path $tmpDir "SHA256SUMS.txt")
    }
    catch {
        Write-Fatal "Failed to download checksums."
    }

    Write-Info "Verifying SHA256 checksum..."
    $checksumLine = Get-Content (Join-Path $tmpDir "SHA256SUMS.txt") | Where-Object { $_ -match $artifact }
    if (-not $checksumLine) {
        Write-Fatal "Binary $artifact not found in SHA256SUMS.txt"
    }
    $expected = ($checksumLine -split '\s+')[0]
    $actual = (Get-FileHash -Path (Join-Path $tmpDir $artifact) -Algorithm SHA256).Hash.ToLower()

    if ($expected -ne $actual) {
        Write-Fatal "Checksum mismatch!`n  Expected: $expected`n  Actual:   $actual"
    }
    Write-Success "Checksum verified"

    return Join-Path $tmpDir $artifact
}

# ── Install binary ────────────────────────────────────────────────────────────

function Install-Binary {
    param($SourcePath)

    Write-Info "Installing binary to $BinaryPath..."
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $SourcePath -Destination $BinaryPath -Force
    Write-Success "Binary installed"
}

# ── Create directories and config ─────────────────────────────────────────────

function Initialize-Config {
    Write-Info "Creating data directories..."
    New-Item -ItemType Directory -Path $KeyDir -Force | Out-Null

    # Restrict key directory ACL to Administrators and SYSTEM only
    $acl = Get-Acl $KeyDir
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl $KeyDir $acl

    if (Test-Path $ConfigPath) {
        Write-Info "Config already exists at $ConfigPath, keeping it"
        return
    }

    Write-Info "Generating config at $ConfigPath..."
    $configContent = @"
# StealthOS Relay Server - Configuration
# Generated by installer on $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

[server]
ws_bind = "0.0.0.0:9090"
metrics_bind = "0.0.0.0:9091"
max_connections = 500
max_message_size = 65536
idle_timeout = 600
handshake_timeout = 10

[pool]
max_pools = 100
max_pool_size = 16
pool_idle_timeout = 300

[crypto]
key_dir = "$($KeyDir -replace '\\', '\\')"
auto_generate_keys = true

[logging]
level = "info"
format = "pretty"

[rate_limit]
connections_per_minute = 30
messages_per_second = 60
max_failed_auth = 5
block_duration_secs = 600
"@

    Set-Content -Path $ConfigPath -Value $configContent -Encoding UTF8
    Write-Success "Config generated"
}

# ── Windows Service ───────────────────────────────────────────────────────────

function Register-RelayService {
    Write-Info "Registering Windows Service..."

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Info "Service already exists, updating..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    $binPathValue = "`"$BinaryPath`" serve --config `"$ConfigPath`""
    $scArgs = @("create", $ServiceName, "binPath=", $binPathValue, "start=", "auto", "DisplayName=", $ServiceDisplayName)
    $scResult = & sc.exe @scArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fatal "Failed to create service: $scResult"
    }
    & sc.exe description $ServiceName "Zero-knowledge WebSocket relay for StealthOS" 2>&1 | Out-Null

    Write-Success "Windows Service registered"
}

function Start-RelayService {
    Write-Info "Starting service..."
    Start-Service -Name $ServiceName
    Write-Success "Service started"
}

function Stop-RelayService {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
    }
}

# ── Wait for health ──────────────────────────────────────────────────────────

function Wait-ForHealth {
    Write-Info "Waiting for server to start..."
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:9091/health" -UseBasicParsing -TimeoutSec 2
            Write-Success "Server is running"
            return $true
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
    Write-Warn "Server may not have started yet. Check Event Viewer for details."
    return $false
}

# ── Show setup URL ────────────────────────────────────────────────────────────

function Show-SetupUrl {
    # For Windows service, the setup URL is in the service log output.
    # Since Windows services don't have easy log access like journalctl,
    # we'll try to read from the Application event log or start the binary
    # briefly to capture the URL.

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor White
    Write-Host "  StealthOS Relay is running!" -ForegroundColor White
    Write-Host ""
    Write-Host "  To claim your server, run this command to see the setup URL:" -ForegroundColor White
    Write-Host ""
    Write-Host "  & `"$BinaryPath`" serve --config `"$ConfigPath`"" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  (Stop the service first: Stop-Service $ServiceName)" -ForegroundColor Gray
    Write-Host "  Or check: http://127.0.0.1:9091/setup" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  WebSocket relay:  ws://0.0.0.0:9090" -ForegroundColor White
    Write-Host "  Health check:     http://127.0.0.1:9091/health" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor White
    Write-Host ""

    if (-not $NoBrowser) {
        Start-Process "http://127.0.0.1:9091/health"
    }
}

# ── Uninstall ─────────────────────────────────────────────────────────────────

function Do-Uninstall {
    Write-Host "StealthOS Relay - Uninstall" -ForegroundColor White
    Write-Host ""

    # Stop and remove service
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Info "Stopping and removing service..."
        Stop-RelayService
        sc.exe delete $ServiceName | Out-Null
        Write-Success "Service removed"
    }

    # Remove binary
    if (Test-Path $InstallDir) {
        Write-Info "Removing installation directory..."
        Remove-Item -Recurse -Force $InstallDir
        Write-Success "Binary removed"
    }

    # Remove config (keep keys separate)
    if (Test-Path $ConfigPath) {
        Write-Info "Removing config..."
        Remove-Item -Force $ConfigPath
        Write-Success "Config removed"
    }

    # Ask about keys
    if (Test-Path $KeyDir) {
        Write-Host ""
        Write-Warn "Key directory found at $KeyDir"
        Write-Warn "This contains your server identity and claim binding."
        Write-Warn "If you delete it, you will need to re-claim the server."
        Write-Host ""
        $confirm = Read-Host "Delete key directory? [y/N]"
        if ($confirm -match "^[Yy]$") {
            Remove-Item -Recurse -Force $DataDir
            Write-Success "Data directory removed"
        }
        else {
            Write-Info "Key directory preserved at $KeyDir"
        }
    }

    Write-Host ""
    Write-Success "StealthOS Relay has been uninstalled."
}

# ── Update ────────────────────────────────────────────────────────────────────

function Do-Update {
    Write-Host "StealthOS Relay - Update" -ForegroundColor White
    Write-Host ""

    if (-not (Test-Path $BinaryPath)) {
        Write-Fatal "StealthRelay is not installed at $BinaryPath. Run without -Update to install."
    }

    Resolve-Version
    $downloadPath = Download-Binary

    Stop-RelayService
    Install-Binary -SourcePath $downloadPath
    Start-RelayService

    Write-Host ""
    Write-Success "StealthOS Relay updated to $Version"
}

# ── Main install ──────────────────────────────────────────────────────────────

function Do-Install {
    Write-Host ""
    Write-Host "StealthOS Relay - Installer" -ForegroundColor White
    Write-Host "Zero-knowledge WebSocket relay for StealthOS" -ForegroundColor Gray
    Write-Host ""

    if (Test-Path $BinaryPath) {
        Write-Warn "StealthRelay is already installed at $BinaryPath"
        Write-Warn "Use -Update to update or -Uninstall to remove first."
        exit 1
    }

    Resolve-Version
    $downloadPath = Download-Binary
    Install-Binary -SourcePath $downloadPath
    Initialize-Config

    if (-not $NoService) {
        Register-RelayService
        Start-RelayService

        if (Wait-ForHealth) {
            Show-SetupUrl
        }
    }
    else {
        Write-Host ""
        Write-Success "Installation complete (no service created)."
        Write-Host ""
        Write-Host "  Start manually with:"
        Write-Host "  & `"$BinaryPath`" serve --config `"$ConfigPath`""
        Write-Host ""
    }
}

# ── Entry point ───────────────────────────────────────────────────────────────

# Check administrator
if (-not (Test-Administrator)) {
    Write-Fatal "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator'."
}

if ($Uninstall) {
    Do-Uninstall
}
elseif ($Update) {
    Do-Update
}
else {
    Do-Install
}
