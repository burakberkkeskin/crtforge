// Command crtforge is a small private CA for test environments.
package main

import (
	"os"
	"runtime/debug"

	"github.com/burakberkkeskin/crtforge/internal/cli"
)

// version is set at release time with -ldflags "-X main.version=v2.0.0".
var version = ""

func main() {
	os.Exit(cli.Execute(resolveVersion(), os.Args[1:], os.Stdout, os.Stderr))
}

// resolveVersion falls back to the module and VCS data Go embeds, so a
// `go install` or local build still reports something useful.
func resolveVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		v = "dev"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			v += "+" + s.Value[:12]
		}
	}
	return v
}
