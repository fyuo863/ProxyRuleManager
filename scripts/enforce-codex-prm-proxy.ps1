[CmdletBinding()]
param(
  [switch]$ApplyUserEnv = $true,
  [switch]$SkipUserEnv,
  [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

function Read-JsonOrNull {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Test-TcpPort {
  param([string]$Address)
  try {
    $hostPart, $portText = $Address -split ':', 2
    $client = [System.Net.Sockets.TcpClient]::new()
    $async = $client.BeginConnect($hostPart, [int]$portText, $null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(2))) {
      $client.Close()
      return @{ ok = $false; error = "timeout" }
    }
    $client.EndConnect($async)
    $client.Close()
    return @{ ok = $true; error = "" }
  } catch {
    return @{ ok = $false; error = $_.Exception.Message }
  }
}

function Get-CodexProcesses {
  @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match '^(Codex|codex)\.exe$' -or $_.ExecutablePath -match 'OpenAI\.Codex'
  } | Select-Object ProcessId, Name, ExecutablePath, CommandLine)
}

function Get-CodexProxyConnections {
  param([int[]]$Pids)
  if (-not $Pids -or $Pids.Count -eq 0) { return @() }
  @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
    $Pids -contains $_.OwningProcess -and
    $_.RemoteAddress -in @('127.0.0.1', '::1') -and
    $_.RemotePort -in @(18088, 18089, 7892)
  } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)
}

$cfgPath = Join-Path $env:USERPROFILE ".PRM\config.json"
$cfg = Read-JsonOrNull $cfgPath
$pacAddr = if ($cfg -and $cfg.pacListenAddr) { $cfg.pacListenAddr } else { "127.0.0.1:18088" }
$proxyAddr = if ($cfg -and $cfg.proxyListenAddr) { $cfg.proxyListenAddr } else { "127.0.0.1:18089" }
$fastLinkAddr = if ($cfg -and $cfg.fastLinkProxyAddr) { $cfg.fastLinkProxyAddr } else { "127.0.0.1:7892" }
$pacUrl = "http://$pacAddr/proxy.pac"
$proxyUrl = "http://$proxyAddr"

$pacTcp = Test-TcpPort $pacAddr
$proxyTcp = Test-TcpPort $proxyAddr
$fastLinkTcp = Test-TcpPort $fastLinkAddr

if (-not $pacTcp.ok) {
  throw "PRM PAC is not reachable at ${pacAddr}: $($pacTcp.error)"
}
if (-not $proxyTcp.ok) {
  throw "PRM proxy is not reachable at ${proxyAddr}: $($proxyTcp.error)"
}
if (-not $fastLinkTcp.ok) {
  throw "FastLink upstream is not reachable at ${fastLinkAddr}: $($fastLinkTcp.error)"
}

if (-not $CheckOnly) {
  $keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
  Set-ItemProperty -Path $keyPath -Name AutoConfigURL -Value $pacUrl
  Set-ItemProperty -Path $keyPath -Name ProxyEnable -Value 0
  Remove-ItemProperty -Path $keyPath -Name ProxyServer -ErrorAction SilentlyContinue

  if ($ApplyUserEnv -and -not $SkipUserEnv) {
    [Environment]::SetEnvironmentVariable("HTTP_PROXY", $proxyUrl, "User")
    [Environment]::SetEnvironmentVariable("HTTPS_PROXY", $proxyUrl, "User")
    [Environment]::SetEnvironmentVariable("ALL_PROXY", $proxyUrl, "User")
    [Environment]::SetEnvironmentVariable("NO_PROXY", "localhost,127.0.0.1,::1", "User")
  }
}

$windowsProxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue |
  Select-Object AutoConfigURL, ProxyEnable, ProxyServer
$userEnv = [ordered]@{
  HTTP_PROXY = [Environment]::GetEnvironmentVariable("HTTP_PROXY", "User")
  HTTPS_PROXY = [Environment]::GetEnvironmentVariable("HTTPS_PROXY", "User")
  ALL_PROXY = [Environment]::GetEnvironmentVariable("ALL_PROXY", "User")
  NO_PROXY = [Environment]::GetEnvironmentVariable("NO_PROXY", "User")
}
$codex = Get-CodexProcesses
$connections = Get-CodexProxyConnections -Pids @($codex | Select-Object -ExpandProperty ProcessId)
$directFastLink = @($connections | Where-Object { $_.RemotePort -eq 7892 })
$throughPrm = @($connections | Where-Object { $_.RemotePort -eq 18089 })
$pacFetch = @($connections | Where-Object { $_.RemotePort -eq 18088 })

Write-Host "Codex PRM constraint configuration"
Write-Host "Mode: $(if ($CheckOnly) { 'check-only' } else { 'applied' })"
Write-Host "PAC URL: $pacUrl"
Write-Host "PRM proxy: $proxyUrl"
Write-Host "FastLink upstream: $fastLinkAddr"
Write-Host ""
Write-Host "Windows proxy:"
$windowsProxy | Format-List
Write-Host "User environment for newly started processes:"
$userEnv.GetEnumerator() | Format-Table -AutoSize
Write-Host "Live Codex processes: $($codex.Count)"
Write-Host "Live Codex -> PAC 18088: $($pacFetch.Count)"
Write-Host "Live Codex -> PRM 18089: $($throughPrm.Count)"
Write-Host "Live Codex -> FastLink 7892 bypass: $($directFastLink.Count)"

if ($connections.Count -gt 0) {
  Write-Host ""
  $connections | Sort-Object OwningProcess, RemotePort, LocalPort | Format-Table -AutoSize
}

if ($directFastLink.Count -gt 0) {
  Write-Host ""
  Write-Host "Existing Codex processes still have direct 7892 connections. This script does not kill them."
  Write-Host "To fully enforce for current Codex, restart Codex after saving this conversation/checkpoint."
} else {
  Write-Host ""
  Write-Host "No live Codex -> FastLink 7892 bypass observed."
}
