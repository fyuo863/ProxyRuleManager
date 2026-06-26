export namespace model {
	
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
	export class Rule {
	    id: string;
	    enabled: boolean;
	    type: string;
	    value: string;
	    target: string;
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
	        this.remark = source["remark"];
	    }
	}
	export class AppConfig {
	    rules: Rule[];
	    pacListenAddr: string;
	    proxyListenAddr: string;
	    fastLinkProxyAddr: string;
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
	        this.fastLinkProxyAddr = source["fastLinkProxyAddr"];
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
	export class TrafficLog {
	    id: string;
	    time: string;
	    host: string;
	    port: string;
	    protocol: string;
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
	        this.host = source["host"];
	        this.port = source["port"];
	        this.protocol = source["protocol"];
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
	    systemPacEnabled: boolean;
	    currentAutoConfigURL: string;
	    fastLinkReachable: boolean;
	    fastLinkMessage: string;
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
	        this.systemPacEnabled = source["systemPacEnabled"];
	        this.currentAutoConfigURL = source["currentAutoConfigURL"];
	        this.fastLinkReachable = source["fastLinkReachable"];
	        this.fastLinkMessage = source["fastLinkMessage"];
	        this.ruleCount = source["ruleCount"];
	        this.enabledRuleCount = source["enabledRuleCount"];
	        this.activeConnectionCount = source["activeConnectionCount"];
	        this.recentLogCount = source["recentLogCount"];
	        this.lastError = source["lastError"];
	    }
	}
	export class AppState {
	    config: AppConfig;
	    status: ServiceStatus;
	    logs: TrafficLog[];
	
	    static createFrom(source: any = {}) {
	        return new AppState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.config = this.convertValues(source["config"], AppConfig);
	        this.status = this.convertValues(source["status"], ServiceStatus);
	        this.logs = this.convertValues(source["logs"], TrafficLog);
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
	        this.duplicate = source["duplicate"];
	    }
	}
	export class BatchRuleRequest {
	    content: string;
	    target: string;
	    remark: string;
	    enabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new BatchRuleRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.content = source["content"];
	        this.target = source["target"];
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

