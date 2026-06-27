package tun

type RuntimeArtifacts struct {
	RuntimeDir     string `json:"runtimeDir"`
	CoreDir        string `json:"coreDir"`
	ConfigPath     string `json:"configPath"`
	LogPath        string `json:"logPath"`
	CoreExecutable string `json:"coreExecutable"`
}
