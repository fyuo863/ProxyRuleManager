[CmdletBinding()]
param(
  [string]$SessionDir
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SessionDir)) {
  $root = Join-Path $env:USERPROFILE ".PRM\diagnostics\monitor-sessions"
  if (-not (Test-Path -LiteralPath $root)) {
    throw "未找到监控会话目录: $root"
  }
  $latest = Get-ChildItem -LiteralPath $root -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $latest) {
    throw "未找到可停止的监控会话"
  }
  $SessionDir = $latest.FullName
}

$stopFile = Join-Path $SessionDir "monitor.stop"
New-Item -ItemType File -Path $stopFile -Force | Out-Null
Write-Host "stop signal written: $stopFile"
