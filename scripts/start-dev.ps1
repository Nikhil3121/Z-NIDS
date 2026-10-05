# Starts the whole Z-NIDS development stack on Windows (no Docker needed):
#   PostgreSQL (5433) -> Redis stand-in (6380) -> API (8010) -> web UI (5180)
# Anything already running is left alone. Usage, from the project folder:
#   powershell -ExecutionPolicy Bypass -File scripts\start-dev.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root "backend\.venv\Scripts\python.exe"
$pgCtl = "C:\Program Files\PostgreSQL\18\bin\pg_ctl.exe"

function Test-Port([int]$port) {
    [bool](Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
}

function Start-Window([string]$title, [string]$command) {
    # Each long-running service gets its own window so its logs stay visible.
    $cmd = "`$Host.UI.RawUI.WindowTitle = 'Z-NIDS $title'; Set-Location '$root'; $command"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $cmd | Out-Null
}

if (-not (Test-Path $python)) { throw "Python venv not found at $python" }
if (-not (Test-Path ".env")) { throw ".env not found in $root (copy .env.example and fill it in)" }

Write-Host "[1/4] PostgreSQL" -ForegroundColor Cyan
if (Test-Port 5433) { Write-Host "      already running on 5433" }
else {
    # Run pg_ctl as a separate hidden process: the postgres server it spawns would
    # otherwise inherit this script's output handle and block it.
    Start-Process -FilePath $pgCtl -WindowStyle Hidden -ArgumentList @(
        "start", "-D", "`"$root\var\pgdata`"", "-l", "`"$root\var\postgres.log`"",
        "-o", "`"-p 5433 -c listen_addresses=127.0.0.1`"") | Out-Null
    for ($i = 0; $i -lt 30 -and -not (Test-Port 5433); $i++) { Start-Sleep 1 }
    if (-not (Test-Port 5433)) { throw "PostgreSQL did not start - see var\postgres.log" }
    Write-Host "      started on 5433"
}

Write-Host "[2/4] Redis stand-in" -ForegroundColor Cyan
if (Test-Port 6380) { Write-Host "      already running on 6380" }
else { Start-Window "Redis" "& '$python' scripts\dev_redis.py --port 6380"; Write-Host "      started on 6380" }

Write-Host "[3/4] API" -ForegroundColor Cyan
if (Test-Port 8010) { Write-Host "      already running on 8010" }
else {
    Start-Window "API" "& '$python' -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8010 --reload --reload-dir backend\app"
    Write-Host "      starting on 8010"
}

Write-Host "[4/4] Web UI" -ForegroundColor Cyan
if (Test-Port 5180) { Write-Host "      already running on 5180" }
else {
    if (-not (Test-Path "frontend\node_modules")) { npm --prefix frontend ci }
    Start-Window "Web" "npm --prefix frontend run dev"
    Write-Host "      starting on 5180"
}

Write-Host "Waiting for the API to become ready..." -NoNewline
$ready = $false
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
    try { $ready = (Invoke-RestMethod http://127.0.0.1:8010/ready -TimeoutSec 2).status -eq "ready" } catch { Start-Sleep 1 }
}
if ($ready) {
    Write-Host " ready." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Web UI   http://localhost:5180"
    Write-Host "  API docs http://127.0.0.1:8010/docs"
    Write-Host "  Admin login is in var\dev-admin.txt"
    Start-Process "http://localhost:5180"
} else {
    Write-Host " not ready after 60 s - check the 'Z-NIDS API' window for errors." -ForegroundColor Red
}
