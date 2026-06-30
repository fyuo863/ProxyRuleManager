export namespace model {
	
	export class NetworkRoute {
	    ifIndex: number;
	    interfaceAlias: string;
	    destination: string;
	    nextHop: string;
	    routeMetric: number;
	    interfaceMetric: number;
	    state: string;
	
	    static createFrom(source: any = {}) {
	        return new NetworkRoute(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ifIndex = source["ifIndex"];
	        this.interfaceAlias = source["interfaceAlias"];
	        this.destination = source["destination"];
	        this.nextHop = source["nextHop"];
	        this.routeMetric = source["routeMetric"];
	        this.interfaceMetric = source["interfaceMetric"];
	        this.state = source["state"];
	    }
	}
	export class TunRuntimeStatus {
	    running: boolean;
	    available: boolean;
	    message: string;
	    packetCount: number;
	    byteCount: number;
	
	    static createFrom(source: any = {}) {
	        return new TunRuntimeStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.available = source["available"];
	        this.message = source["message"];
	        this.packetCount = source["packetCount"];
	        this.byteCount = source["byteCount"];
	    }
	}
	export class UpstreamProxyRouteStatus {
	    applied: boolean;
	    message: string;
	    interfaceAlias: string;
	    gateway: string;
	    routeCount: number;
	    targets: string[];
	
	    static createFrom(source: any = {}) {
	        return new UpstreamProxyRouteStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.applied = source["applied"];
	        this.message = source["message"];
	        this.interfaceAlias = source["interfaceAlias"];
	        this.gateway = source["gateway"];
	        this.routeCount = source["routeCount"];
	        this.targets = source["targets"];
	    }
	}
	export class ProxyGuardRuntimeStatus {
	    applied: boolean;
	    message: string;
	    programCount: number;
	    blockedInterfaceCount: number;
	
	    static createFrom(source: any = {}) {
	        return new ProxyGuardRuntimeStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.applied = source["applied"];
	        this.message = source["message"];
	        this.programCount = source["programCount"];
	        this.blockedInterfaceCount = source["blockedInterfaceCount"];
	    }
	}
	export class NetworkAdapterOption {
	    name: string;
	    description: string;
	    status: string;
	
	    static createFrom(source: any = {}) {
	        return new NetworkAdapterOption(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.status = source["status"];
	    }
	}
	export class ManagedAppStatus {
	    query: string;
	    name: string;
	    path: string;
	    running: boolean;
	    pidCount: number;
	    activeConnections: number;
	
	    static createFrom(source: any = {}) {
	        return new ManagedAppStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.query = source["query"];
	        this.name = source["name"];
	        this.path = source["path"];
	        this.running = source["running"];
	        this.pidCount = source["pidCount"];
	        this.activeConnections = source["activeConnections"];
	    }
	}
	export class TrafficLog {
	    id: string;
	    time: string;
	    source: string;
	    host: string;
	    port: string;
	    protocol: string;
	    processId: number;
	    processName: string;
	    processPath: string;
	    matchedRuleType: string;
	    matchedRuleValue: string;
	    matchedRuleIndex: number;
	    target: string;
	    path: string;
	    uploadBytes: number;
	    downloadBytes: number;
	    durationMs: number;
	    status: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new TrafficLog(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.time = source["time"];
	        this.source = source["source"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.protocol = source["protocol"];
	        this.processId = source["processId"];
	        this.processName = source["processName"];
	        this.processPath = source["processPath"];
	        this.matchedRuleType = source["matchedRuleType"];
	        this.matchedRuleValue = source["matchedRuleValue"];
	        this.matchedRuleIndex = source["matchedRuleIndex"];
	        this.target = source["target"];
	        this.path = source["path"];
	        this.uploadBytes = source["uploadBytes"];
	        this.downloadBytes = source["downloadBytes"];
	        this.durationMs = source["durationMs"];
	        this.status = source["status"];
	        this.error = source["error"];
	    }
	}
	export class ServiceStatus {
	    pacRunning: boolean;
	    pacUrl: string;
	    proxyRunning: boolean;
	    proxyAddr: string;
	    upstreamProxyRouteApplied: boolean;
	    upstreamProxyRouteMessage: string;
	    upstreamProxyRouteCount: number;
	    proxyGuardApplied: boolean;
	    proxyGuardMessage: string;
	    proxyGuardProgramCount: number;
	    tunRunning: boolean;
	    tunAvailable: boolean;
	    tunMessage: string;
	    tunIncludedAppCount: number;
	    managedAppCount: number;
	    managedProcessCount: number;
	    managedConnectionCount: number;
	    tunPacketCount: number;
	    tunByteCount: number;
	    systemPacEnabled: boolean;
	    currentAutoConfigURL: string;
	    upstreamProxyReachable: boolean;
	    upstreamProxyMessage: string;
	    ruleCount: number;
	    enabledRuleCount: number;
	    activeConnectionCount: number;
	    recentLogCount: number;
	    lastError: string;
	
	    static createFrom(source: any = {}) {
	        return new ServiceStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pacRunning = source["pacRunning"];
	        this.pacUrl = source["pacUrl"];
	        this.proxyRunning = source["proxyRunning"];
	        this.proxyAddr = source["proxyAddr"];
	        this.upstreamProxyRouteApplied = source["upstreamProxyRouteApplied"];
	        this.upstreamProxyRouteMessage = source["upstreamProxyRouteMessage"];
	        this.upstreamProxyRouteCount = source["upstreamProxyRouteCount"];
	        this.proxyGuardApplied = source["proxyGuardApplied"];
	        this.proxyGuardMessage = source["proxyGuardMessage"];
	        this.proxyGuardProgramCount = source["proxyGuardProgramCount"];
	        this.tunRunning = source["tunRunning"];
	        this.tunAvailable = source["tunAvailable"];
	        this.tunMessage = source["tunMessage"];
	        this.tunIncludedAppCount = source["tunIncludedAppCount"];
	        this.managedAppCount = source["managedAppCount"];
	        this.managedProcessCount = source["managedProcessCount"];
	        this.managedConnectionCount = source["managedConnectionCount"];
	        this.tunPacketCount = source["tunPacketCount"];
	        this.tunByteCount = source["tunByteCount"];
	        this.systemPacEnabled = source["systemPacEnabled"];
	        this.currentAutoConfigURL = source["currentAutoConfigURL"];
	        this.upstreamProxyReachable = source["upstreamProxyReachable"];
	        this.upstreamProxyMessage = source["upstreamProxyMessage"];
	        this.ruleCount = source["ruleCount"];
	        this.enabledRuleCount = source["enabledRuleCount"];
	        this.activeConnectionCount = source["activeConnectionCount"];
	        this.recentLogCount = source["recentLogCount"];
	        this.lastError = source["lastError"];
	    }
	}
	export class WindowsProxyConfig {
	    autoConfigURL: string;
	    proxyEnable: boolean;
	    proxyServer: string;
	
	    static createFrom(source: any = {}) {
	        return new WindowsProxyConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.autoConfigURL = source["autoConfigURL"];
	        this.proxyEnable = source["proxyEnable"];
	        this.proxyServer = source["proxyServer"];
	    }
	}
	export class TunAppProfile {
	    id: string;
	    name: string;
	    enabled: boolean;
	    queries: string[];
	    routingMode: string;
	    remark: string;
	
	    static createFrom(source: any = {}) {
	        return new TunAppProfile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.enabled = source["enabled"];
	        this.queries = source["queries"];
	        this.routingMode = source["routingMode"];
	        this.remark = source["remark"];
	    }
	}
	export class Rule {
	    id: string;
	    enabled: boolean;
	    type: string;
	    value: string;
	    target: string;
	    folder: string;
	    remark: string;
	
	    static createFrom(source: any = {}) {
	        return new Rule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.enabled = source["enabled"];
	        this.type = source["type"];
	        this.value = source["value"];
	        this.target = source["target"];
	        this.folder = source["folder"];
	        this.remark = source["remark"];
	    }
	}
	export class AppConfig {
	    rules: Rule[];
	    pacListenAddr: string;
	    proxyListenAddr: string;
	    upstreamProxyAddr: string;
	    upstreamProxyType: string;
	    proxyInterfaceName: string;
	    upstreamProxyRouteEnabled: boolean;
	    upstreamProxyRouteInterface: string;
	    upstreamProxyRouteTargets: string[];
	    proxyGuardEnabled: boolean;
	    proxyGuardInterface: string;
	    proxyGuardProgramPaths: string[];
	    directInterfaceName: string;
	    tunInterfaceName: string;
	    tunAddressCidr: string;
	    tunMtu: number;
	    tunAppProfiles: TunAppProfile[];
	    tunIncludedApps: string[];
	    autoStartTunService: boolean;
	    autoStartPacService: boolean;
	    autoStartProxyService: boolean;
	    autoEnableSystemPac: boolean;
	    disableSystemPacOnExit: boolean;
	    maxLogEntries: number;
	    savedWindowsProxyConfig?: WindowsProxyConfig;
	
	    static createFrom(source: any = {}) {
	        return new AppConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.rules = this.convertValues(source["rules"], Rule);
	        this.pacListenAddr = source["pacListenAddr"];
	        this.proxyListenAddr = source["proxyListenAddr"];
	        this.upstreamProxyAddr = source["upstreamProxyAddr"];
	        this.upstreamProxyType = source["upstreamProxyType"];
	        this.proxyInterfaceName = source["proxyInterfaceName"];
	        this.upstreamProxyRouteEnabled = source["upstreamProxyRouteEnabled"];
	        this.upstreamProxyRouteInterface = source["upstreamProxyRouteInterface"];
	        this.upstreamProxyRouteTargets = source["upstreamProxyRouteTargets"];
	        this.proxyGuardEnabled = source["proxyGuardEnabled"];
	        this.proxyGuardInterface = source["proxyGuardInterface"];
	        this.proxyGuardProgramPaths = source["proxyGuardProgramPaths"];
	        this.directInterfaceName = source["directInterfaceName"];
	        this.tunInterfaceName = source["tunInterfaceName"];
	        this.tunAddressCidr = source["tunAddressCidr"];
	        this.tunMtu = source["tunMtu"];
	        this.tunAppProfiles = this.convertValues(source["tunAppProfiles"], TunAppProfile);
	        this.tunIncludedApps = source["tunIncludedApps"];
	        this.autoStartTunService = source["autoStartTunService"];
	        this.autoStartPacService = source["autoStartPacService"];
	        this.autoStartProxyService = source["autoStartProxyService"];
	        this.autoEnableSystemPac = source["autoEnableSystemPac"];
	        this.disableSystemPacOnExit = source["disableSystemPacOnExit"];
	        this.maxLogEntries = source["maxLogEntries"];
	        this.savedWindowsProxyConfig = this.convertValues(source["savedWindowsProxyConfig"], WindowsProxyConfig);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AppState {
	    config: AppConfig;
	    status: ServiceStatus;
	    logs: TrafficLog[];
	    managedApps: ManagedAppStatus[];
	    availableNetworkAdapters: NetworkAdapterOption[];
	
	    static createFrom(source: any = {}) {
	        return new AppState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.config = this.convertValues(source["config"], AppConfig);
	        this.status = this.convertValues(source["status"], ServiceStatus);
	        this.logs = this.convertValues(source["logs"], TrafficLog);
	        this.managedApps = this.convertValues(source["managedApps"], ManagedAppStatus);
	        this.availableNetworkAdapters = this.convertValues(source["availableNetworkAdapters"], NetworkAdapterOption);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DiagnosticPaths {
	    rootDir: string;
	    configPath: string;
	    legacyConfigPath: string;
	    diagnosticsPath: string;
	    tunRuntimeDir: string;
	    tunConfigPath: string;
	    tunLogPath: string;
	    coreDir: string;
	    coreExecutable: string;
	
	    static createFrom(source: any = {}) {
	        return new DiagnosticPaths(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.rootDir = source["rootDir"];
	        this.configPath = source["configPath"];
	        this.legacyConfigPath = source["legacyConfigPath"];
	        this.diagnosticsPath = source["diagnosticsPath"];
	        this.tunRuntimeDir = source["tunRuntimeDir"];
	        this.tunConfigPath = source["tunConfigPath"];
	        this.tunLogPath = source["tunLogPath"];
	        this.coreDir = source["coreDir"];
	        this.coreExecutable = source["coreExecutable"];
	    }
	}
	export class AgentDiagnostics {
	    generatedAt: string;
	    paths: DiagnosticPaths;
	    state: AppState;
	    proxyGuard: ProxyGuardRuntimeStatus;
	    upstreamProxyRoute: UpstreamProxyRouteStatus;
	    tunStatus: TunRuntimeStatus;
	    networkAdapters: NetworkAdapterOption[];
	    defaultIpv4Routes: NetworkRoute[];
	    currentWindowsProxy?: WindowsProxyConfig;
	    tunConfigPreview: string;
	    tunLogTail: string;
	    recentLogs: TrafficLog[];
	    fullLogs: TrafficLog[];
	
	    static createFrom(source: any = {}) {
	        return new AgentDiagnostics(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.generatedAt = source["generatedAt"];
	        this.paths = this.convertValues(source["paths"], DiagnosticPaths);
	        this.state = this.convertValues(source["state"], AppState);
	        this.proxyGuard = this.convertValues(source["proxyGuard"], ProxyGuardRuntimeStatus);
	        this.upstreamProxyRoute = this.convertValues(source["upstreamProxyRoute"], UpstreamProxyRouteStatus);
	        this.tunStatus = this.convertValues(source["tunStatus"], TunRuntimeStatus);
	        this.networkAdapters = this.convertValues(source["networkAdapters"], NetworkAdapterOption);
	        this.defaultIpv4Routes = this.convertValues(source["defaultIpv4Routes"], NetworkRoute);
	        this.currentWindowsProxy = this.convertValues(source["currentWindowsProxy"], WindowsProxyConfig);
	        this.tunConfigPreview = source["tunConfigPreview"];
	        this.tunLogTail = source["tunLogTail"];
	        this.recentLogs = this.convertValues(source["recentLogs"], TrafficLog);
	        this.fullLogs = this.convertValues(source["fullLogs"], TrafficLog);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class BatchRuleItem {
	    raw: string;
	    type: string;
	    value: string;
	    target: string;
	    folder: string;
	    duplicate: boolean;
	
	    static createFrom(source: any = {}) {
	        return new BatchRuleItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.raw = source["raw"];
	        this.type = source["type"];
	        this.value = source["value"];
	        this.target = source["target"];
	        this.folder = source["folder"];
	        this.duplicate = source["duplicate"];
	    }
	}
	export class BatchRuleRequest {
	    content: string;
	    target: string;
	    folder: string;
	    remark: string;
	    enabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new BatchRuleRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.content = source["content"];
	        this.target = source["target"];
	        this.folder = source["folder"];
	        this.remark = source["remark"];
	        this.enabled = source["enabled"];
	    }
	}
	export class BatchRuleResult {
	    state: AppState;
	    addedCount: number;
	    mergedCount: number;
	    skipped: BatchRuleItem[];
	    added: BatchRuleItem[];
	
	    static createFrom(source: any = {}) {
	        return new BatchRuleResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = this.convertValues(source["state"], AppState);
	        this.addedCount = source["addedCount"];
	        this.mergedCount = source["mergedCount"];
	        this.skipped = this.convertValues(source["skipped"], BatchRuleItem);
	        this.added = this.convertValues(source["added"], BatchRuleItem);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	
	
	
	
	
	
	

}

