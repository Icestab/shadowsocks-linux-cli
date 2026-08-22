package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/Icestab/shadowsocks-linux-cli/internal/config"
	"github.com/Icestab/shadowsocks-linux-cli/internal/daemon"
)

func newStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start sscli (TUN + routing + DNS + sslocal)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.Start(loadConfigFn)
		},
	}
}

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop sscli and restore network state",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.Stop()
		},
	}
}

func newRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart sscli",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := daemon.Stop(); err != nil && err != daemon.ErrNotRunning {
				fmt.Println("stop:", err)
			}
			return daemon.Start(loadConfigFn)
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show sscli runtime status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.Status(cmd.OutOrStdout())
		},
	}
}

// loadConfigFn adapts the CLI flag handling for the daemon package.
func loadConfigFn() (*config.Config, error) { return loadConfig() }

var _ io.Writer = nil // placeholder to keep io imported until status output lands
