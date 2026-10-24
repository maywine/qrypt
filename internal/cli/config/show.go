package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
	cliruntime "github.com/yinzhenyu/qrypt/internal/cli/runtime"
	"github.com/yinzhenyu/qrypt/pkg/drive"
)

func NewShowCmd(rt cliruntime.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show config with secrets masked",
		Long: `Print the resolved config file with secret values (passwords, salts,
and driver secrets) replaced by ******.`,
		Example: `  qrypt config show
  qrypt config show --config ./qrypt.toml`,
		Args: cliruntime.NoArgs(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, err := rt.CommandConfigPath(cmd)
			if err != nil {
				return err
			}
			if configPath == "" {
				return rt.ConfigNotFoundError()
			}
			raw, err := os.ReadFile(configPath)
			if err != nil {
				return fmt.Errorf("read config: %w", err)
			}

			var cfg map[string]any
			if err := toml.Unmarshal(raw, &cfg); err != nil {
				// Parser errors can include credential values from the input.
				if parseErr, ok := err.(toml.ParseError); ok {
					return fmt.Errorf("parse config: invalid TOML at line %d", parseErr.Position.Line)
				}
				return fmt.Errorf("parse config: invalid TOML")
			}

			knownSecrets := map[string]bool{"password": true, "salt": true, "token": true}
			for _, name := range drive.Names() {
				for _, p := range drive.ParamSchema(name) {
					if p.Secret {
						knownSecrets[p.Name] = true
					}
				}
			}

			maskSecrets(cfg, knownSecrets)
			return toml.NewEncoder(cmd.OutOrStdout()).Encode(cfg)
		},
	}
	rt.WithConfigFlag(cmd)
	return cmd
}

func maskSecrets(value any, secrets map[string]bool) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			// Match the TOML decoder's Unicode case folding for struct fields.
			for secret := range secrets {
				if strings.EqualFold(key, secret) && child != "" {
					value[key] = "******"
					break
				}
			}
			maskSecrets(value[key], secrets)
		}
	case []map[string]any:
		for _, child := range value {
			maskSecrets(child, secrets)
		}
	case []any:
		for _, child := range value {
			maskSecrets(child, secrets)
		}
	}
}
