// Package version owns product identity independently of upstream release versions.
package version

import (
	"runtime"
	"runtime/debug"
)

const (
	ConfigSchema   = 1
	DatabaseSchema = 4
	ProtocolABI    = 1
	APIVersion     = "v1"
)

// Inject with -ldflags; building never generates or rewrites source.
var (
	ProductVersion = "devel"
	Commit         = ""
	Dirty          = ""
	BuildTime      = "unknown"
)

type Info struct {
	Product        string `json:"product"`
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	Dirty          bool   `json:"dirty"`
	BuildTime      string `json:"build_time"`
	GoVersion      string `json:"go_version"`
	Platform       string `json:"platform"`
	UpstreamTag    string `json:"upstream_tag"`
	UpstreamCommit string `json:"upstream_commit"`
	Channel        string `json:"channel"`
	APIVersion     string `json:"api_version"`
}

func Current() Info {
	i := Info{Product: "Splicore", Version: ProductVersion, Commit: Commit, Dirty: Dirty == "true", BuildTime: BuildTime, GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH, UpstreamTag: "v1.14.1", UpstreamCommit: "1ac1a339cb1223e9c70eae14c44411c75033c02d", Channel: "development", APIVersion: APIVersion}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, s := range build.Settings {
			switch s.Key {
			case "vcs.revision":
				if i.Commit == "" {
					i.Commit = s.Value
				}
			case "vcs.modified":
				if Dirty == "" {
					i.Dirty = s.Value == "true"
				}
			}
		}
	}
	if i.Commit == "" {
		i.Commit = "unknown"
	}
	return i
}
