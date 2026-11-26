# Install desktop-bridge on Windows as a Scheduled Task that starts at logon and restarts on crash.
# Run in PowerShell from the install directory:  powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1
#   -Forward -Name NAME -SshHost HOST -LocalPort 18799 [-RemotePort 8788]   # panel machine: SSH forward to a remote
param([switch]$Forward, [string]$Name, [string]$SshHost, [int]$LocalPort, [int]$RemotePort = 8788)
$ErrorActionPreference = "Stop"
$Dir = (Resolve-Path "$PSScriptRoot\..\..").Path
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
if ($Forward) {
  if (-not $Name -or -not $SshHost -or -not $LocalPort) { throw "usage: -Forward -Name NAME -SshHost HOST -LocalPort PORT [-RemotePort 8788]" }
  $Action = New-ScheduledTaskAction -Execute "ssh.exe" -Argument "-N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -L 127.0.0.1:${LocalPort}:127.0.0.1:${RemotePort} $SshHost"
  Register-ScheduledTask -TaskName "desktop-bridge-forward-$Name" -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
  Start-ScheduledTask -TaskName "desktop-bridge-forward-$Name"
  Write-Host "Add $Name=http://127.0.0.1:$LocalPort to MB_REMOTES in .env and restart the desktop-bridge task."
} else {
  $Action = New-ScheduledTaskAction -Execute "$Dir\deploy\windows\run-server.cmd" -WorkingDirectory $Dir
  Register-ScheduledTask -TaskName "desktop-bridge" -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
  Start-ScheduledTask -TaskName "desktop-bridge"
  Write-Host "desktop-bridge task registered and started. Health: http://127.0.0.1:8787/healthz"
}
