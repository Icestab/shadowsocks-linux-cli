// Command sscli is a native Linux CLI Shadowsocks routing client.
package main

import (
	"os"

	"github.com/Icestab/sscli/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
