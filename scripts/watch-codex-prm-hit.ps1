[CmdletBinding()]
param(
  [int]$IntervalSeconds = 5,
  [int]$Iterations = 1,
  [int]$TailLines = 240
)

$ErrorActionPreference = "Stop"

function Get-CodexProcesses {
  @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match '^(Codex|codex)\.exe$' -or $_.ExecutablePath -match 'OpenAI\.Codex'
  } | Select-Object ProcessId, Name, ExecutablePath, CommandLine)
}

function Get-EndpointConnections {
  param([int[]]$Pids)
  if (-not $Pids -or $Pids.Count -eq 0) { return @() }
  @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
    $Pids -contains $_.OwningProcess -and (
      ($_.RemoteAddress -in @('127.0.0.1', '::1') -and $_.RemotePort -in @(18088, 18089, 7892)) -or
      ($_.LocalAddress -in @('127.0.0.1', '::1') -and $_.LocalPort -in @(18088, 18089, 7892))
    )
  } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)
}

function Read-AgentHits {
  $diag = Join-Path $env:USERPROFILE ".PRM\diagnostics\agent-diagnostics.json"
  if (-not (Test-Path -LiteralPath $diag)) { return @() }
  try {
    $j = Get-Content -LiteralPath $diag -Raw -Encoding UTF8 | ConvertFrom-Json
    return @($j.state.logs | Where-Object {
      $_.processName -match 'codex' -or
      $_.processPath -match 'OpenAI\.Codex' -or
      $_.matchedRuleValue -match 'APP:Codex' -or
      $_.host -match 'openai|chatgpt|oaistatic|oaiusercontent'
    } | Select-Object -Last 40 time, source, host, port, processName, matchedRuleType, matchedRuleValue, target, status, path, error)
  } catch {
    return @()
  }
}

function Read-TransparentHits {
  param([int]$Lines)
  $log = Join-Path $env:USERPROFILE ".PRM\tun-runtime\app-transparent.log"
  if (-not (Test-Path -LiteralPath $log)) { return @() }
  @(Select-String -LiteralPath $log -Pattern 'Codex\.exe|codex\.exe|127\.0\.0\.1:18088|127\.0\.0\.1:18089|127\.0\.0\.1:7892|transparent tunnel established|socket connect matched|socket connect skipped loopback' -CaseSensitive:$false |
    Select-Object -Last $Lines |
    ForEach-Object { $_.Line })
}

function Write-Sample {
  $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $codex = Get-CodexProcesses
  $pids = @($codex | Select-Object -ExpandProperty ProcessId)
  $endpointConnections = Get-EndpointConnections -Pids $pids
  $agentHits = Read-AgentHits
  $transparentHits = Read-TransparentHits -Lines $TailLines

  $toPac = @($endpointConnections | Where-Object { $_.RemotePort -eq 18088 -or $_.LocalPort -eq 18088 })
  $toPrm = @($endpointConnections | Where-Object { $_.RemotePort -eq 18089 -or $_.LocalPort -eq 18089 })
  $toFastLink = @($endpointConnections | Where-Object { $_.RemotePort -eq 7892 -or $_.LocalPort -eq 7892 })
  $appHits = @($agentHits | Where-Object { $_.matchedRuleValue -match 'APP:Codex' })
  $webHits = @($agentHits | Where-Object { $_.host -match 'openai|chatgpt|oaistatic|oaiusercontent' -and $_.target -eq 'PROXY' })
  $transparentMatched = @($transparentHits | Where-Object { $_ -match 'socket connect matched query=Codex|transparent tunnel established .*codex' })
  $loopbackSkipped = @($transparentHits | Where-Object { $_ -match 'skipped loopback .*127\.0\.0\.1:(18088|18089|7892)' })

  Write-Host ""
  Write-Host "[$now] Codex PRM hit watch"
  Write-Host "Codex process count: $($codex.Count)"
  Write-Host "Live Codex -> PAC 18088 connections: $($toPac.Count)"
  Write-Host "Live Codex -> PRM proxy 18089 connections: $($toPrm.Count)"
  Write-Host "Live Codex -> FastLink 7892 connections: $($toFastLink.Count)"
  Write-Host "Agent log APP:Codex hits: $($appHits.Count)"
  Write-Host "Agent log OpenAI/ChatGPT PROXY hits: $($webHits.Count)"
  Write-Host "Transparent matched Codex lines in tail: $($transparentMatched.Count)"
  Write-Host "Loopback skipped lines in tail: $($loopbackSkipped.Count)"
  if ($toFastLink.Count -eq 0 -and ($toPrm.Count -gt 0 -or $appHits.Count -gt 0 -or $webHits.Count -gt 0)) {
    Write-Host "Constraint: OK - no live Codex -> FastLink 7892 bypass observed in this sample."
  } elseif ($toFastLink.Count -gt 0) {
    Write-Host "Constraint: BYPASS - live Codex -> FastLink 7892 connections still exist."
  } else {
    Write-Host "Constraint: UNKNOWN - no live Codex PRM/FastLink endpoint connection in this sample."
  }

  if ($endpointConnections.Count -gt 0) {
    Write-Host ""
    Write-Host "Live endpoint connections:"
    $endpointConnections | Sort-Object OwningProcess, RemotePort, LocalPort | Format-Table -AutoSize
  }

  if ($agentHits.Count -gt 0) {
    Write-Host ""
    Write-Host "Recent PRM traffic hits:"
    $agentHits | Select-Object -Last 12 time, source, host, port, processName, matchedRuleValue, target, status | Format-Table -AutoSize
  }

  if ($transparentHits.Count -gt 0) {
    Write-Host ""
    Write-Host "Recent transparent log lines:"
    $transparentHits | Select-Object -Last 16
  }
}

for ($i = 0; $i -lt $Iterations; $i++) {
  Write-Sample
  if ($i -lt ($Iterations - 1)) {
    Start-Sleep -Seconds $IntervalSeconds
  }
}
