<#
.SYNOPSIS
    Verify the local environment can run AgentSec before starting work.

.DESCRIPTION
    Checks the host toolchain, Docker daemon, WSL2 resource caps, uv environment
    location, and GitHub CLI auth. Reports PASS / WARN / FAIL per check and exits
    non-zero if any FAIL is present.

    WARN means "works, but not as intended" - most commonly WSL2 running on its
    defaults (50% of host RAM, every logical processor), which is the single most
    likely cause of host resource starvation on a shared workstation.

.EXAMPLE
    pwsh -File scripts/preflight.ps1
#>

[CmdletBinding()]
param(
    [switch]$Fix
)

$ErrorActionPreference = 'Continue'
$script:Failures = 0
$script:Warnings = 0

function Write-Check {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL')][string]$Status,
        [Parameter(Mandatory)][string]$Name,
        [string]$Detail = ''
    )
    $colour = switch ($Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } }
    Write-Host ("  [{0}] " -f $Status) -ForegroundColor $colour -NoNewline
    Write-Host $Name -NoNewline
    if ($Detail) { Write-Host "  $Detail" -ForegroundColor DarkGray } else { Write-Host '' }
    if ($Status -eq 'FAIL') { $script:Failures++ }
    if ($Status -eq 'WARN') { $script:Warnings++ }
}

function Test-Command {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host "`nAgentSec preflight" -ForegroundColor Cyan
Write-Host ("=" * 60)

# --- toolchain -------------------------------------------------------------
Write-Host "`nToolchain" -ForegroundColor Cyan

if (Test-Command 'python') {
    $v = (& python --version 2>&1) -replace 'Python\s*', ''
    $parsed = [version]($v -split '\+')[0]
    if ($parsed -ge [version]'3.12') { Write-Check PASS 'Python >= 3.12' "found $v" }
    else { Write-Check FAIL 'Python >= 3.12' "found $v" }
} else {
    Write-Check FAIL 'Python >= 3.12' 'python not on PATH'
}

if (Test-Command 'uv') {
    Write-Check PASS 'uv' ((& uv --version 2>&1) -join ' ')
} else {
    Write-Check FAIL 'uv' 'not on PATH - see https://docs.astral.sh/uv/'
}

# make is deliberately NOT required; the task runner is uv.
if (Test-Command 'make') {
    Write-Check PASS 'make (optional)' 'present'
} else {
    Write-Check PASS 'make (optional)' 'absent - not required, uv is the task runner'
}

# --- docker ----------------------------------------------------------------
Write-Host "`nDocker" -ForegroundColor Cyan

if (-not (Test-Command 'docker')) {
    Write-Check FAIL 'docker CLI' 'not on PATH'
} else {
    Write-Check PASS 'docker CLI' ((& docker --version 2>&1) -join ' ')

    $info = & docker info --format '{{.ServerVersion}}|{{.OSType}}|{{.NCPU}}|{{.MemTotal}}' 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Check FAIL 'Docker daemon' 'not running - start Docker Desktop'
    } else {
        $parts = ($info -join '') -split '\|'
        $memGb = [math]::Round([int64]$parts[3] / 1GB, 1)
        Write-Check PASS 'Docker daemon' "v$($parts[0]) $($parts[1]), $($parts[2]) CPUs, $memGb GB"

        if ($parts[1] -ne 'linux') {
            Write-Check FAIL 'Linux containers' "OSType is $($parts[1]); switch to Linux containers"
        }
    }
}

# --- WSL2 resource caps (G25) ---------------------------------------------
Write-Host "`nResource caps" -ForegroundColor Cyan

$wslConfig = Join-Path $env:USERPROFILE '.wslconfig'
if (Test-Path $wslConfig) {
    $content = Get-Content $wslConfig -Raw
    $hasMemory = $content -match '(?m)^\s*memory\s*='
    $hasProcs = $content -match '(?m)^\s*processors\s*='
    if ($hasMemory -and $hasProcs) {
        $m = ([regex]'(?m)^\s*memory\s*=\s*(\S+)').Match($content).Groups[1].Value
        $p = ([regex]'(?m)^\s*processors\s*=\s*(\S+)').Match($content).Groups[1].Value
        Write-Check PASS 'WSL2 caps' "memory=$m processors=$p"
    } else {
        Write-Check WARN 'WSL2 caps' '.wslconfig exists but does not cap both memory and processors'
    }
} else {
    $detail = 'no ~/.wslconfig - WSL2 will take 50% of RAM and all logical CPUs'
    if ($Fix) {
        @(
            '[wsl2]'
            'memory=16GB'
            'processors=12'
            'swap=8GB'
        ) | Set-Content -Path $wslConfig -Encoding utf8
        Write-Check PASS 'WSL2 caps' "created $wslConfig (run 'wsl --shutdown' to apply)"
    } else {
        Write-Check WARN 'WSL2 caps' "$detail - rerun with -Fix to create it"
    }
}

# --- uv environment location ----------------------------------------------
Write-Host "`nEnvironment" -ForegroundColor Cyan

$repoRoot = Split-Path -Parent $PSScriptRoot
if ($env:UV_PROJECT_ENVIRONMENT) {
    $envPath = $env:UV_PROJECT_ENVIRONMENT
    if ($envPath -like "$repoRoot*") {
        Write-Check WARN 'UV_PROJECT_ENVIRONMENT' 'points inside the repo; OneDrive will sync the venv'
    } else {
        Write-Check PASS 'UV_PROJECT_ENVIRONMENT' $envPath
    }
} else {
    Write-Check WARN 'UV_PROJECT_ENVIRONMENT' 'unset - venv will land in the OneDrive-synced repo'
}

if ($repoRoot -like '*OneDrive*') {
    Write-Check WARN 'Repo location' 'under OneDrive - never bind-mount this path into a container'
} else {
    Write-Check PASS 'Repo location' 'outside OneDrive'
}

# --- github ---------------------------------------------------------------
Write-Host "`nGitHub" -ForegroundColor Cyan

if (-not (Test-Command 'gh')) {
    Write-Check WARN 'gh CLI' 'not on PATH - only needed to create/push the repo'
} else {
    $null = & gh auth status 2>&1
    if ($LASTEXITCODE -eq 0) {
        $who = & gh api user --jq .login 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Check PASS 'gh auth' "authenticated as $who"
        } else {
            Write-Check FAIL 'gh auth' 'status ok but API call failed - token may lack scopes'
        }
    } else {
        Write-Check FAIL 'gh auth' "not authenticated - run 'gh auth login'"
    }
}

# --- package integrity ----------------------------------------------------
Write-Host "`nExecution package" -ForegroundColor Cyan

$validator = Join-Path $PSScriptRoot 'validate_package.py'
if (Test-Path $validator) {
    $out = & python $validator 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Check PASS 'Package validator' (($out | Select-Object -First 1) -replace '^OK:\s*', '')
    } else {
        Write-Check FAIL 'Package validator' 'validation failed - run it directly for detail'
    }
} else {
    Write-Check FAIL 'Package validator' 'scripts/validate_package.py missing'
}

# --- summary --------------------------------------------------------------
Write-Host "`n$('=' * 60)"
if ($script:Failures -gt 0) {
    Write-Host "PREFLIGHT FAILED - $($script:Failures) failure(s), $($script:Warnings) warning(s)`n" -ForegroundColor Red
    exit 1
}
if ($script:Warnings -gt 0) {
    Write-Host "PREFLIGHT PASSED WITH WARNINGS - $($script:Warnings) warning(s)`n" -ForegroundColor Yellow
    exit 0
}
Write-Host "PREFLIGHT PASSED`n" -ForegroundColor Green
exit 0
