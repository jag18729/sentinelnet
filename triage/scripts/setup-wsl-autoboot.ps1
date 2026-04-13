# WSL Auto-Boot Setup for XPS
# Run this script as Administrator from the Windows desktop.
# It creates a scheduled task that starts WSL on system boot (before user login)
# and writes a .wslconfig to cap WSL memory at 14GB.

# Self-elevate if not admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$ErrorActionPreference = 'Stop'

Write-Host "=== WSL Auto-Boot Setup ===" -ForegroundColor Cyan

# 1. Create scheduled task
Write-Host "`n[1/2] Creating scheduled task 'WSL-AutoBoot'..." -ForegroundColor Yellow

$taskName = "WSL-AutoBoot"

# Remove existing task if present
Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-d Ubuntu -u root -- /bin/true"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Boot WSL2 Ubuntu at system startup so Tailscale and Ollama start without user login" | Out-Null

$task = Get-ScheduledTask -TaskName $taskName
Write-Host "  Task '$taskName' registered (status: $($task.State))"
Write-Host "  Trigger: At system startup, runs as SYSTEM"
Write-Host "  Action: wsl.exe -d Ubuntu -u root -- /bin/true"

# 2. Write .wslconfig
Write-Host "`n[2/2] Writing .wslconfig..." -ForegroundColor Yellow

$wslConfigPath = "$env:USERPROFILE\.wslconfig"
$wslConfig = @"
[wsl2]
memory=14GB
swap=0
"@

Set-Content -Path $wslConfigPath -Value $wslConfig -Encoding UTF8
Write-Host "  Wrote $wslConfigPath"
Write-Host "  memory=14GB (leaves 2GB for Windows)"
Write-Host "  swap=0 (prevent disk thrashing)"

# Summary
Write-Host "`n=== Done ===" -ForegroundColor Cyan
Write-Host "On next Windows reboot:"
Write-Host "  1. Task Scheduler runs wsl.exe before any user logs in"
Write-Host "  2. WSL boots with systemd=true (per /etc/wsl.conf)"
Write-Host "  3. systemd starts tailscaled + ollama automatically"
Write-Host "  4. XPS appears on the tailnet within ~30 seconds of boot"
Write-Host ""
Write-Host "Verify after reboot:"
Write-Host "  From any tailnet peer: curl -sS http://100.73.127.58:11434/api/version"
Write-Host "  Or: tailscale status | grep xps"
Write-Host ""
Write-Host "To remove: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
