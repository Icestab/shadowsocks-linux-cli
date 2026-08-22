// Command sscli is a native Linux CLI Shadowsocks routing client.
package main

import (
	"os"

	"github.com/Icestab/shadowsocks-linux-cli/internal/cli"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := cli.Execute(version); err != nil {
		os.Exit(1)
	}
}
