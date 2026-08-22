// Package cli implements the sscli command tree.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Icestab/shadowsocks-linux-cli/internal/config"
)

var (
	cfgPath string
	verbose bool
	debug   bool
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sscli",
		Short: "Native Linux Shadowsocks TUN routing client",
		Long: `sscli takes over system traffic through a Linux TUN device and routes it
DIRECT or through a Shadowsocks proxy according to GFW List, China domain/IP
lists, LAN rules and the selected mode (gfw | bypass | global).

Shadowsocks encryption is handled by a managed sslocal (shadowsocks-rust)
subprocess; sscli never re-implements the protocol.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&cfgPath, "config", "", "path to config.yaml (default ~/.config/sscli/config.yaml)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "debug logging (implies -v)")

	root.AddCommand(
		newStartCmd(),
		newStopCmd(),
		newRestartCmd(),
		newStatusCmd(),
		newTestCmd(),
		newUpdateCmd(),
		newRulesCmd(),
		newRouteCmd(),
		newDNSCmd(),
		newConfigCmd(),
		newModeCmd(),
	)
	return root
}

// Execute runs the root command; errors are printed once here.
func Execute() error {
	cmd := NewRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return err
	}
	return nil
}

// resolveConfigPath returns the effective config path.
func resolveConfigPath() (string, error) {
	if cfgPath != "" {
		return cfgPath, nil
	}
	return config.DefaultPath()
}

// loadConfig loads the effective config file.
func loadConfig() (*config.Config, error) {
	p, err := resolveConfigPath()
	if err != nil {
		return nil, err
	}
	return config.Load(p)
}
