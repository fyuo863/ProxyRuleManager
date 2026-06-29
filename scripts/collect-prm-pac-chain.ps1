[CmdletBinding()]
param(
  [string]$OutputRoot = "$env:USERPROFILE\.PRM\diagnostics\pac-chain-checks",
  [int]$TimeoutSeconds = 8,
  [string]$TestUrl = "https://www.google.com/generate_204"
)

$ErrorActionPreference = "Stop"

function Ensure-Dir {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Read-JsonOrNull {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Tail-OrNull {
  param([string]$Path, [int]$Lines = 160)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  return (Get-Content -LiteralPath $Path -Tail $Lines -ErrorAction SilentlyContinue) -join "`r`n"
}

function Test-TcpPort {
  param([string]$Address)
  try {
    $client = [System.Net.Sockets.TcpClient]::new()
    $async = $client.BeginConnect(($Address -split ':')[0], [int](($Address -split ':')[-1]), $null, $null)
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

function Invoke-CurlStatus {
  param([string]$Proxy, [string]$Url)
  $curlArgs = @("-I", "-L", "--silent", "--show-error", "--max-time", "$TimeoutSeconds", "-x", $Proxy, $Url)
  $quotedArgs = $curlArgs | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }
  $cmdLine = "curl.exe $($quotedArgs -join ' ') 2>&1"
  $output = & cmd.exe /d /c $cmdLine
  $exitCode = $LASTEXITCODE
  $statusLines = @($output | Where-Object { $_ -match '^HTTP/' })
  return @{
    proxy = $Proxy
    url = $Url
    statusLines = $statusLines
    outputTail = @($output | Select-Object -Last 20)
    exitCode = $exitCode
  }
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutputRoot $stamp
Ensure-Dir $outDir

$prmRoot = Join-Path $env:USERPROFILE ".PRM"
$configPath = Join-Path $prmRoot "config.json"
$diagPath = Join-Path $prmRoot "diagnostics\agent-diagnostics.json"
$transparentLogPath = Join-Path $prmRoot "tun-runtime\app-transparent.log"

$config = Read-JsonOrNull $configPath
$agentDiagnostics = Read-JsonOrNull $diagPath
$pacAddr = if ($config -and $config.pacListenAddr) { $config.pacListenAddr } else { "127.0.0.1:18088" }
$proxyAddr = if ($config -and $config.proxyListenAddr) { $config.proxyListenAddr } else { "127.0.0.1:18089" }
$fastLinkAddr = if ($config -and $config.fastLinkProxyAddr) { $config.fastLinkProxyAddr } else { "127.0.0.1:7892" }

$windowsProxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue |
  Select-Object AutoConfigURL, ProxyEnable, ProxyServer, AutoDetect

$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -in @(([int](($pacAddr -split ':')[-1])), ([int](($proxyAddr -split ':')[-1])), ([int](($fastLinkAddr -split ':')[-1]))) } |
  Select-Object LocalAddress, LocalPort, OwningProcess, State)

$processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match 'ProxyRuleManager|FastLink|Codex|codex' -or $_.CommandLine -match 'ProxyRuleManager|FastLink|Codex|codex'
} | Select-Object ProcessId, Name, ExecutablePath, CommandLine)

$pacUrl = "http://$pacAddr/proxy.pac"
$pacFetch = @{
  url = $pacUrl
  ok = $false
  status = ""
  body = ""
  error = ""
}
try {
  $resp = Invoke-WebRequest -Uri $pacUrl -UseBasicParsing -TimeoutSec 3
  $pacFetch.ok = $true
  $pacFetch.status = [string]$resp.StatusCode
  if ($resp.Content -is [byte[]]) {
    $pacFetch.body = [System.Text.Encoding]::UTF8.GetString($resp.Content)
  } else {
    $pacFetch.body = [string]$resp.Content
  }
} catch {
  $pacFetch.error = $_.Exception.Message
}

$fastLinkTcp = Test-TcpPort $fastLinkAddr
$prmProxyTcp = Test-TcpPort $proxyAddr
$pacTcp = Test-TcpPort $pacAddr

$fastLinkExternal = $null
if ($fastLinkTcp.ok) {
  $fastLinkExternal = Invoke-CurlStatus -Proxy "http://$fastLinkAddr" -Url $TestUrl
}

$prmExternal = $null
if ($prmProxyTcp.ok) {
  $prmExternal = Invoke-CurlStatus -Proxy "http://$proxyAddr" -Url $TestUrl
}

$result = [ordered]@{
  capturedAt = (Get-Date).ToString("o")
  outputDir = $outDir
  configPath = $configPath
  agentDiagnosticsPath = $diagPath
  addresses = [ordered]@{
    pac = $pacAddr
    prmProxy = $proxyAddr
    fastLink = $fastLinkAddr
    pacUrl = $pacUrl
    testUrl = $TestUrl
  }
  windowsProxy = $windowsProxy
  configFlags = if ($config) {
    [ordered]@{
      autoStartPacService = $config.autoStartPacService
      autoStartProxyService = $config.autoStartProxyService
      autoEnableSystemPac = $config.autoEnableSystemPac
      disableSystemPacOnExit = $config.disableSystemPacOnExit
      savedWindowsProxyConfig = $config.savedWindowsProxyConfig
    }
  } else { $null }
  tcp = [ordered]@{
    pac = $pacTcp
    prmProxy = $prmProxyTcp
    fastLink = $fastLinkTcp
    listeners = $listeners
  }
  pacFetch = $pacFetch
  externalTests = [ordered]@{
    throughFastLink = $fastLinkExternal
    throughPrmProxy = $prmExternal
  }
  processes = $processes
  agentStatus = if ($agentDiagnostics -and $agentDiagnostics.state) { $agentDiagnostics.state.status } else { $null }
  transparentLogTail = Tail-OrNull $transparentLogPath
}

$jsonPath = Join-Path $outDir "pac-chain-check.json"
$txtPath = Join-Path $outDir "pac-chain-summary.txt"
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$summary = @(
  "capturedAt: $($result.capturedAt)"
  "windows AutoConfigURL: $($windowsProxy.AutoConfigURL)"
  "windows ProxyEnable: $($windowsProxy.ProxyEnable)"
  "windows ProxyServer: $($windowsProxy.ProxyServer)"
  "PAC $pacAddr tcp: $($pacTcp.ok) $($pacTcp.error)"
  "PRM proxy $proxyAddr tcp: $($prmProxyTcp.ok) $($prmProxyTcp.error)"
  "FastLink $fastLinkAddr tcp: $($fastLinkTcp.ok) $($fastLinkTcp.error)"
  "PAC fetch: $($pacFetch.ok) status=$($pacFetch.status) error=$($pacFetch.error)"
  "PAC body: $($pacFetch.body)"
  "FastLink external status: $(if ($fastLinkExternal) { ($fastLinkExternal.statusLines -join ' | ') } else { 'not tested' })"
  "PRM external status: $(if ($prmExternal) { ($prmExternal.statusLines -join ' | ') } else { 'not tested' })"
  "json: $jsonPath"
)
$summary | Set-Content -LiteralPath $txtPath -Encoding UTF8

Write-Host "PAC chain check written:"
Write-Host $txtPath
Write-Host $jsonPath
Get-Content -LiteralPath $txtPath
