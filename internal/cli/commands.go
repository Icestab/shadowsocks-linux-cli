package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dy/sscli/internal/config"
)

func newTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Run connectivity and rule self-tests",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return runSelfTest(cmd.OutOrStdout(), cfg)
		},
	}
}

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update GFW List / China domain / China IP rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return updateRules(cmd.OutOrStdout(), cfg)
		},
	}
}

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect loaded rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return showRules(cmd.OutOrStdout(), cfg)
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "update",
		Short: "Alias of 'sscli update'",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return updateRules(cmd.OutOrStdout(), cfg)
		},
	})
	return cmd
}

func newRouteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "route",
		Short: "Show routing decisions for targets or current route state",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return showRoute(cmd.OutOrStdout(), cfg, args)
		},
	}
}

func newDNSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dns <domain>",
		Short: "Resolve a domain through sscli's DNS module and show its routing decision",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return dnsQuery(cmd.OutOrStdout(), cfg, args[0])
		},
	}
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show effective configuration (passwords redacted)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			showConfig(cmd.OutOrStdout(), cfg)
			return nil
		},
	}
	cmd.AddCommand(newConfigInitCmd())
	return cmd
}

func newConfigInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Write a commented default config to the config path",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := resolveConfigPath()
			if err != nil {
				return err
			}
			return config.InitDefault(path)
		},
	}
}

var _ = fmt.Println // keep fmt until stubs below are implemented
