// Command sscli is a native Linux CLI Shadowsocks routing client.
package main

import (
	"os"

	"github.com/Icestab/shadowsocks-linux-cli/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
