# Stops the Z-NIDS development stack started by start-dev.ps1.
#   powershell -ExecutionPolicy Bypass -File scripts\stop-dev.ps1
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

foreach ($port in 5180, 8010, 6380) {
    $conns = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
    foreach ($procId in ($conns.OwningProcess | Sort-Object -Unique)) {
        # taskkill /T also ends the uvicorn reloader / npm child processes.
        taskkill /PID $procId /T /F | Out-Null
        Write-Host "stopped port $port (pid $procId)"
    }
}
if (Get-NetTCPConnection -State Listen -LocalPort 5433 -ErrorAction SilentlyContinue) {
    & "C:\Program Files\PostgreSQL\18\bin\pg_ctl.exe" stop -D var\pgdata | Out-Null
    Write-Host "stopped PostgreSQL"
}
