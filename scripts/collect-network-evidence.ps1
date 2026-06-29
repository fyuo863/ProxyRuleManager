[CmdletBinding()]
param(
  [int]$IntervalSeconds = 15,
  [string]$OutputRoot = "$env:USERPROFILE\.PRM\diagnostics\monitor-sessions",
  [switch]$Once
)

$ErrorActionPreference = "Stop"

function Write-Log {
  param([string]$Message)
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[$timestamp] $Message"
}

function Ensure-Dir {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Copy-IfExists {
  param(
    [string]$Source,
    [string]$Destination
  )
  if (Test-Path -LiteralPath $Source) {
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    return $true
  }
  return $false
}

function Save-Json {
  param(
    [string]$Path,
    [object]$Value
  )
  $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Save-Text {
  param(
    [string]$Path,
    [string]$Text
  )
  Set-Content -LiteralPath $Path -Value $Text -Encoding UTF8
}

function Count-Items {
  param([object]$Value)
  if ($null -eq $Value) {
    return 0
  }
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    return @($Value).Count
  }
  return 1
}

function Load-JsonFile {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    return $null
  }
  try {
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Tail-File {
  param(
    [string]$Path,
    [int]$Lines = 400
  )
  if (-not (Test-Path -LiteralPath $Path)) {
    return $null
  }
  return (Get-Content -LiteralPath $Path -Tail $Lines -ErrorAction SilentlyContinue) -join "`r`n"
}

function Get-LatestLogFiles {
  param(
    [string]$Root,
    [int]$MaxFiles = 8
  )
  if (-not (Test-Path -LiteralPath $Root)) {
    return @()
  }
  return @(Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First $MaxFiles)
}

function Capture-Snapshot {
  param(
    [string]$SessionDir,
    [string]$SnapshotDir
  )

  Ensure-Dir $SnapshotDir

  $prmRoot = Join-Path $env:USERPROFILE ".PRM"
  $diagPath = Join-Path $prmRoot "diagnostics\agent-diagnostics.json"
  $configPath = Join-Path $prmRoot "config.json"
  $transparentConfigPath = Join-Path $prmRoot "tun-runtime\transparent-runtime.json"
  $tunLogPath = Join-Path $prmRoot "tun-runtime\app-transparent.log"
  $codexLogRoot = Join-Path $env:LOCALAPPDATA "Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\Codex\Logs"
  $fastLinkRoots = @(
    "D:\Program Files\FastLink",
    (Join-Path $env:APPDATA "FastLink"),
    (Join-Path $env:LOCALAPPDATA "FastLink")
  )

  Copy-IfExists -Source $diagPath -Destination (Join-Path $SnapshotDir "agent-diagnostics.json") | Out-Null
  Copy-IfExists -Source $configPath -Destination (Join-Path $SnapshotDir "config.json") | Out-Null
  Copy-IfExists -Source $transparentConfigPath -Destination (Join-Path $SnapshotDir "transparent-runtime.json") | Out-Null

  $tcpEstablished = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State)
  $tcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State)
  $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess)

  $snapshot = [ordered]@{
    capturedAt = (Get-Date).ToString("o")
    computerName = $env:COMPUTERNAME
    userName = $env:USERNAME
    codexProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
      $_.Name -match "^codex" -or $_.ExecutablePath -match "OpenAI\.Codex"
    } | Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate)
    fastLinkProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
      $_.Name -in @("FastLink.exe", "FastLinkCore.exe")
    } | Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate)
    adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, InterfaceIndex)
    ipConfig = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceIndex, @{Name="IPv4";Expression={@($_.IPv4Address | Select-Object -ExpandProperty IPAddress)}}, @{Name="IPv4Gateway";Expression={@($_.IPv4DefaultGateway | Select-Object -ExpandProperty NextHop)}}, @{Name="IPv6";Expression={@($_.IPv6Address | Select-Object -ExpandProperty IPAddress)}}, @{Name="IPv6Gateway";Expression={@($_.IPv6DefaultGateway | Select-Object -ExpandProperty NextHop)}}, DNSServer)
    routesV4 = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object DestinationPrefix, RouteMetric, InterfaceMetric | Select-Object ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric, State)
    routesV6 = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | Sort-Object DestinationPrefix, RouteMetric, InterfaceMetric | Select-Object ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric, State)
    tcpEstablishedV4 = @($tcpEstablished | Where-Object { $_.LocalAddress -notmatch ":" -and $_.RemoteAddress -notmatch ":" })
    tcpEstablishedV6 = @($tcpEstablished | Where-Object { $_.LocalAddress -match ":" -or $_.RemoteAddress -match ":" })
    tcpListeners = $tcpListeners
    udpEndpoints = $udpEndpoints
    firewallRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
      $_.DisplayName -match "Codex|FastLink|ProxyRuleManager|Transparent|IPv6"
    } | Select-Object DisplayName, Group, Enabled, Direction, Action, Profile)
  }

  Save-Json -Path (Join-Path $SnapshotDir "network-snapshot.json") -Value $snapshot

  $agentDiagnostics = Load-JsonFile -Path $diagPath
  $configJson = Load-JsonFile -Path $configPath
  $transparentConfig = Load-JsonFile -Path $transparentConfigPath
  $windowsProxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue |
    Select-Object AutoConfigURL, ProxyEnable, ProxyServer

  $agentDiagnosticsFull = [ordered]@{
    capturedAt = $snapshot.capturedAt
    sourceFiles = [ordered]@{
      agentDiagnostics = $diagPath
      config = $configPath
      transparentRuntime = $transparentConfigPath
      transparentLog = $tunLogPath
    }
    appSettings = $configJson
    transparentRuntime = $transparentConfig
    copiedAgentDiagnostics = $agentDiagnostics
    windowsProxy = $windowsProxy
    networkSnapshot = [ordered]@{
      codexProcesses = $snapshot.codexProcesses
      fastLinkProcesses = $snapshot.fastLinkProcesses
      adapters = $snapshot.adapters
      ipConfig = $snapshot.ipConfig
      routesV4 = $snapshot.routesV4
      routesV6 = $snapshot.routesV6
      firewallRules = $snapshot.firewallRules
    }
  }
  Save-Json -Path (Join-Path $SnapshotDir "agent-diagnostics-full.json") -Value $agentDiagnosticsFull

  $stateLogs = @()
  $recentLogs = @()
  $trafficStatus = $null
  $managedApps = @()
  $stateConfig = $null
  $serviceStatus = $null
  $availableNetworkAdapters = @()
  $diagnosticPaths = $null
  $proxyGuardStatus = $null
  $fastLinkRouteStatus = $null
  $tunStatus = $null
  $networkAdapters = @()
  $defaultIpv4Routes = @()
  $currentWindowsProxy = $null
  if ($agentDiagnostics) {
    if ($null -ne $agentDiagnostics.recentLogs) {
      $recentLogs = @($agentDiagnostics.recentLogs)
    }
    if ($agentDiagnostics.PSObject.Properties.Name -contains 'fullLogs' -and $null -ne $agentDiagnostics.fullLogs) {
      $fullLogs = @($agentDiagnostics.fullLogs)
    } else {
      $fullLogs = @()
    }
    $diagnosticPaths = $agentDiagnostics.paths
    $proxyGuardStatus = $agentDiagnostics.proxyGuard
    $fastLinkRouteStatus = $agentDiagnostics.fastLinkRoute
    $tunStatus = $agentDiagnostics.tunStatus
    if ($null -ne $agentDiagnostics.networkAdapters) {
      $networkAdapters = @($agentDiagnostics.networkAdapters)
    }
    if ($null -ne $agentDiagnostics.defaultIpv4Routes) {
      $defaultIpv4Routes = @($agentDiagnostics.defaultIpv4Routes)
    }
    $currentWindowsProxy = $agentDiagnostics.currentWindowsProxy
    if ($agentDiagnostics.state) {
      if ($null -ne $agentDiagnostics.state.logs) {
        $stateLogs = @($agentDiagnostics.state.logs)
      }
      $trafficStatus = $agentDiagnostics.state.status
      if ($null -ne $agentDiagnostics.state.managedApps) {
        $managedApps = @($agentDiagnostics.state.managedApps)
      }
      $stateConfig = $agentDiagnostics.state.config
      $serviceStatus = $agentDiagnostics.state.status
      if ($null -ne $agentDiagnostics.state.availableNetworkAdapters) {
        $availableNetworkAdapters = @($agentDiagnostics.state.availableNetworkAdapters)
      }
    }
  }
  else {
    $fullLogs = @()
  }

  $trafficLogFull = [ordered]@{
    capturedAt = $snapshot.capturedAt
    sourceFiles = [ordered]@{
      agentDiagnostics = $diagPath
      transparentLog = $tunLogPath
    }
    stateLogs = $stateLogs
    fullLogs = $fullLogs
    recentLogs = $recentLogs
    trafficStatus = $trafficStatus
    managedApps = $managedApps
    codexProcesses = $snapshot.codexProcesses
    tcpEstablishedV4 = $snapshot.tcpEstablishedV4
    tcpEstablishedV6 = $snapshot.tcpEstablishedV6
    tcpListeners = $snapshot.tcpListeners
    udpEndpoints = $snapshot.udpEndpoints
  }
  Save-Json -Path (Join-Path $SnapshotDir "traffic-log-full.json") -Value $trafficLogFull

  $settingsLogFull = [ordered]@{
    capturedAt = $snapshot.capturedAt
    sourceFiles = [ordered]@{
      config = $configPath
      agentDiagnostics = $diagPath
      transparentRuntime = $transparentConfigPath
    }
    appSettings = $configJson
    stateConfig = $stateConfig
    serviceStatus = $serviceStatus
    diagnosticPaths = $diagnosticPaths
    proxyGuard = $proxyGuardStatus
    fastLinkRoute = $fastLinkRouteStatus
    tunStatus = $tunStatus
    networkAdapters = $networkAdapters
    availableNetworkAdapters = $availableNetworkAdapters
    defaultIpv4Routes = $defaultIpv4Routes
    currentWindowsProxy = $currentWindowsProxy
    registryWindowsProxy = $windowsProxy
    transparentRuntime = $transparentConfig
    networkSnapshot = [ordered]@{
      adapters = $snapshot.adapters
      ipConfig = $snapshot.ipConfig
      routesV4 = $snapshot.routesV4
      routesV6 = $snapshot.routesV6
      firewallRules = $snapshot.firewallRules
      fastLinkProcesses = $snapshot.fastLinkProcesses
    }
  }
  Save-Json -Path (Join-Path $SnapshotDir "settings-log-full.json") -Value $settingsLogFull

  $tunTail = Tail-File -Path $tunLogPath -Lines 600
  if ($null -ne $tunTail) {
    Save-Text -Path (Join-Path $SnapshotDir "prm-transparent-tail.log") -Text $tunTail
  }
  Copy-IfExists -Source $tunLogPath -Destination (Join-Path $SnapshotDir "prm-transparent-full.log") | Out-Null

  $codexLogFiles = Get-LatestLogFiles -Root $codexLogRoot -MaxFiles 10
  if ($codexLogFiles.Count -gt 0) {
    $codexDir = Join-Path $SnapshotDir "codex-logs"
    Ensure-Dir $codexDir
    foreach ($file in $codexLogFiles) {
      $safeName = "{0:yyyyMMdd-HHmmss}_{1}" -f $file.LastWriteTime, $file.Name
      Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $codexDir $safeName) -Force
    }
  }

  $fastLinkCopies = 0
  foreach ($root in $fastLinkRoots) {
    $files = Get-LatestLogFiles -Root $root -MaxFiles 6 | Where-Object {
      $_.Extension -in @(".log", ".txt", ".json")
    }
    if ($files.Count -eq 0) {
      continue
    }
    $targetDir = Join-Path $SnapshotDir "fastlink-logs"
    Ensure-Dir $targetDir
    foreach ($file in $files) {
      $safeName = "{0}_{1:yyyyMMdd-HHmmss}_{2}" -f ([IO.Path]::GetFileName($file.DirectoryName)), $file.LastWriteTime, $file.Name
      Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $targetDir $safeName) -Force
      $fastLinkCopies++
    }
  }

  $summary = [ordered]@{
    capturedAt = $snapshot.capturedAt
    codexProcessCount = $snapshot.codexProcesses.Count
    fastLinkProcessCount = $snapshot.fastLinkProcesses.Count
    tcpEstablishedV4Count = $snapshot.tcpEstablishedV4.Count
    tcpEstablishedV6Count = $snapshot.tcpEstablishedV6.Count
    tcpListenerCount = $snapshot.tcpListeners.Count
    udpEndpointCount = $snapshot.udpEndpoints.Count
    copiedCodexLogs = $codexLogFiles.Count
    copiedFastLinkLogs = $fastLinkCopies
    copiedAgentDiagnostics = [bool]$agentDiagnostics
    copiedConfig = [bool]$configJson
    copiedTransparentRuntime = [bool]$transparentConfig
    trafficLogEntryCount = Count-Items $fullLogs
    recentTrafficLogEntryCount = Count-Items $recentLogs
    settingsRuleCount = Count-Items $(if ($configJson) { @($configJson.rules) } else { @() })
    copiedTransparentFullLog = [bool](Test-Path -LiteralPath (Join-Path $SnapshotDir "prm-transparent-full.log"))
  }
  Save-Json -Path (Join-Path $SnapshotDir "summary.json") -Value $summary
}

Ensure-Dir $OutputRoot
$sessionId = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionDir = Join-Path $OutputRoot $sessionId
Ensure-Dir $sessionDir

$stopFile = Join-Path $sessionDir "monitor.stop"
$pidFile = Join-Path $sessionDir "monitor.pid"
$metaFile = Join-Path $sessionDir "session.json"

Set-Content -LiteralPath $pidFile -Value $PID -Encoding ASCII
Save-Json -Path $metaFile -Value ([ordered]@{
  sessionId = $sessionId
  startedAt = (Get-Date).ToString("o")
  intervalSeconds = $IntervalSeconds
  stopFile = $stopFile
  pidFile = $pidFile
  host = $env:COMPUTERNAME
})

Write-Log "evidence session started: $sessionDir"
Write-Log "stop file: $stopFile"

do {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $snapshotDir = Join-Path $sessionDir $stamp
  try {
    Capture-Snapshot -SessionDir $sessionDir -SnapshotDir $snapshotDir
    Write-Log "snapshot captured: $snapshotDir"
  } catch {
    $errorPath = Join-Path $snapshotDir "capture-error.txt"
    Ensure-Dir $snapshotDir
    Set-Content -LiteralPath $errorPath -Value $_ | Out-Null
    Write-Log "snapshot failed: $($_.Exception.Message)"
  }

  if ($Once) {
    break
  }
  Start-Sleep -Seconds $IntervalSeconds
} while (-not (Test-Path -LiteralPath $stopFile))

Write-Log "evidence session stopped: $sessionDir"
