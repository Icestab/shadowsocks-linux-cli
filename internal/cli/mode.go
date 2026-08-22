package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dy/sscli/internal/config"
)

func newModeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mode [gfw|bypass|global]",
		Short: "Show or switch the routing mode",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := resolveConfigPath()
			if err != nil {
				return err
			}
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Current mode: %s\n", cfg.Mode)
				return nil
			}
			newMode := config.Mode(args[0])
			if err := newMode.Validate(); err != nil {
				return err
			}
			if newMode == cfg.Mode {
				fmt.Fprintf(cmd.OutOrStdout(), "Current mode: %s (unchanged)\n", cfg.Mode)
				return nil
			}
			if err := config.SetMode(path, newMode); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Mode changed: %s -> %s\n", cfg.Mode, newMode)
			fmt.Fprintln(cmd.OutOrStdout(), "Run 'sudo sscli restart' to apply.")
			return nil
		},
	}
	return cmd
}

// setConfigMode rewrites only the top-level "mode" key of the YAML file,
// preserving comments and key order as much as yaml.v3 Node allows.
func setConfigMode(path string, _, next config.Mode) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return fmt.Errorf("config is empty")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("config root must be a mapping")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "mode" {
			root.Content[i+1].Value = string(next)
			root.Content[i+1].Tag = "!!str"
			break
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil { // config may contain secrets: keep 0600
		return err
	}
	return os.Rename(tmp, path)
}
