# gcp-sa-key-manager auto-update and install script for Windows.
# Usage:
#   irm https://raw.githubusercontent.com/jay0lee/go-sa-key-manager/main/scripts/update.ps1 | iex
#   powershell -ExecutionPolicy Bypass -File scripts\update.ps1 [-CheckOnly] [-Force] [-Version vX.Y.Z] [-InstallDir C:\path]

[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$Force,
    [string]$Version,
    [string]$InstallDir
)

$ErrorActionPreference = "Stop"

$Repo = "jay0lee/go-sa-key-manager"
$BinaryName = "gcp-sa-key-manager.exe"

# 1. Detect Architecture
$Arch = $null
$RawArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($RawArch) {
    ([System.Runtime.InteropServices.Architecture]::X64) {
        $Arch = "windows-amd64"
    }
    ([System.Runtime.InteropServices.Architecture]::Arm64) {
        $Arch = "windows-arm64"
    }
    Default {
        # Fallback to environment variable
        $EnvArch = $env:PROCESSOR_ARCHITECTURE
        if ($EnvArch -eq "AMD64") {
            $Arch = "windows-amd64"
        } elseif ($EnvArch -eq "ARM64") {
            $Arch = "windows-arm64"
        } else {
            throw "Unsupported CPU architecture: $RawArch ($EnvArch). Supported architectures: X64, Arm64."
        }
    }
}

# 2. Locate Existing Installation & Target Directory
$ExistingCmd = Get-Command "gcp-sa-key-manager" -ErrorAction SilentlyContinue
$CurrentVersion = $null

if ($ExistingCmd -and (Test-Path $ExistingCmd.Source)) {
    try {
        $VerOutput = & $ExistingCmd.Source version 2>$null
        if ($VerOutput -match "gcp-sa-key-manager version ([^\s]+)") {
            $CurrentVersion = $matches[1]
        }
    } catch {
        # Ignore error reading existing version
    }
    if (-not $InstallDir) {
        $InstallDir = Split-Path $ExistingCmd.Source -Parent
    }
}

if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\gcp-sa-key-manager"
}

$TargetPath = Join-Path $InstallDir $BinaryName

# 3. Determine Target Version from GitHub API
if (-not $Version) {
    Write-Host "Checking for latest release from https://github.com/$Repo..."
    $Headers = @{
        "User-Agent" = "gcp-sa-key-manager-updater"
        "Accept"     = "application/vnd.github+json"
    }
    try {
        $ReleaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $Headers -UseBasicParsing
        $Version = $ReleaseInfo.tag_name
    } catch {
        throw "Failed to query GitHub Releases API: $_"
    }
}

if (-not $Version) {
    throw "Unable to resolve target version."
}

Write-Host "Current version : $(if ($CurrentVersion) { $CurrentVersion } else { 'not installed' })"
Write-Host "Target version  : $Version"
Write-Host "Platform        : $Arch"
Write-Host "Target path     : $TargetPath"

# Check if already up-to-date
if ($CurrentVersion -and ($CurrentVersion -eq $Version) -and (-not $Force)) {
    Write-Host "✓ gcp-sa-key-manager is already up to date ($CurrentVersion)." -ForegroundColor Green
    return
}

if ($CheckOnly) {
    if ($CurrentVersion -ne $Version) {
        Write-Host "→ An update is available: $CurrentVersion -> $Version" -ForegroundColor Yellow
    } else {
        Write-Host "✓ Up to date." -ForegroundColor Green
    }
    return
}

# 4. Download Release Archive & Checksums
$ArchiveName = "gcp-sa-key-manager-${Arch}.zip"
$BaseUrl = "https://github.com/$Repo/releases/download/$Version"
$DownloadUrl = "$BaseUrl/$ArchiveName"
$ChecksumsUrl = "$BaseUrl/checksums.txt"

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $TempArchive = Join-Path $TempDir $ArchiveName
    $TempChecksums = Join-Path $TempDir "checksums.txt"

    Write-Host "Downloading $ArchiveName..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempArchive -UseBasicParsing

    Write-Host "Downloading checksums.txt..."
    Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TempChecksums -UseBasicParsing

    # 5. Verify Checksum
    Write-Host "Verifying checksum..."
    $ChecksumContent = Get-Content -Path $TempChecksums
    $ExpectedSha = $null
    foreach ($Line in $ChecksumContent) {
        if ($Line -match "([a-fA-F0-9]{64})\s+.*$([regex]::Escape($ArchiveName))") {
            $ExpectedSha = $matches[1].ToLower()
            break
        }
    }

    if (-not $ExpectedSha) {
        throw "Archive $ArchiveName not found in checksums.txt"
    }

    $ActualSha = (Get-FileHash -Path $TempArchive -Algorithm SHA256).Hash.ToLower()
    if ($ActualSha -ne $ExpectedSha) {
        throw "Checksum verification failed!`n  Expected: $ExpectedSha`n  Actual:   $ActualSha"
    }
    Write-Host "✓ Checksum verified ($ActualSha)" -ForegroundColor Green

    # 6. Extract Archive
    Write-Host "Extracting $ArchiveName..."
    Expand-Archive -Path $TempArchive -DestinationPath $TempDir -Force

    # Find the extracted executable
    $ExtractedBin = Join-Path $TempDir $BinaryName
    if (-not (Test-Path $ExtractedBin)) {
        $ExtractedBin = Join-Path $TempDir "gcp-sa-key-manager-${Arch}.exe"
    }
    if (-not (Test-Path $ExtractedBin)) {
        $Found = Get-ChildItem -Path $TempDir -Filter "*.exe" | Select-Object -First 1
        if ($Found) {
            $ExtractedBin = $Found.FullName
        }
    }

    if (-not (Test-Path $ExtractedBin)) {
        throw "Executable not found in extracted archive."
    }

    # 7. Install to Destination
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Write-Host "Installing to $TargetPath..."
    Copy-Item -Path $ExtractedBin -Destination $TargetPath -Force

    # 8. Verify Installation
    $InstalledVer = & $TargetPath version 2>$null
    Write-Host "✓ Successfully installed gcp-sa-key-manager ($Version)" -ForegroundColor Green

    # 9. Update PATH environment variable if needed
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathParts = $UserPath -split ";"
    if ($PathParts -notcontains $InstallDir) {
        Write-Host ""
        Write-Host "Adding '$InstallDir' to User PATH environment variable..."
        $NewPath = "$UserPath;$InstallDir"
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "✓ PATH updated. Restart your shell or terminal for changes to take effect." -ForegroundColor Green
    }
} finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
