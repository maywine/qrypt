package driver

import (
	"context"
	"fmt"
	"os"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
	cliruntime "github.com/yinzhenyu/qrypt/internal/cli/runtime"
	"github.com/yinzhenyu/qrypt/pkg/config"
	"github.com/yinzhenyu/qrypt/pkg/core"
)

func NewLoginCmd(rt LoginRuntime) *cobra.Command {
	cmd := &cobra.Command{
		Use:       "login PROVIDER",
		Short:     "Scan a web login QR code and save credentials to a mount",
		Args:      cliruntime.ExactNamedArgs(rt, "PROVIDER"),
		ValidArgs: []string{"quark"},
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			flow, err := core.NewWebLogin(provider)
			if err != nil {
				return err
			}
			path, err := rt.CommandConfigPath(cmd)
			if err != nil {
				return err
			}
			if path == "" {
				path = "qrypt.toml"
			}
			name, _ := cmd.Flags().GetString("mount")
			if name == "" {
				name = provider
			}
			cfg, err := loadLoginConfig(path)
			if err != nil {
				return err
			}
			if _, err := loginMount(cfg, provider, name); err != nil {
				return err
			}
			if err := config.ValidateGlobal(cfg); err != nil {
				return err
			}
			timeout, _ := cmd.Flags().GetDuration("timeout")
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be greater than 0")
			}
			ctx, stop := rt.ShutdownContext(cmd)
			defer stop()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			challenge, err := flow.Start(ctx)
			if err != nil {
				return err
			}
			qr, err := qrcode.New(challenge.URL, qrcode.Medium)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Scan with the Quark app and confirm login:")
			fmt.Fprint(cmd.ErrOrStderr(), qr.ToSmallString(false))
			for {
				result, err := flow.Poll(ctx)
				if err != nil {
					return err
				}
				switch result.State {
				case core.WebLoginConfirmed:
					if err := ctx.Err(); err != nil {
						return err
					}
					if err := saveLoginConfig(path, provider, name, result.Params); err != nil {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "Logged in. Saved mount %q to %s.\n", name, path)
					return nil
				case core.WebLoginExpired:
					return fmt.Errorf("web login QR code expired; run the command again")
				}
				timer := time.NewTimer(2 * time.Second)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				}
			}
		},
	}
	cmd.Flags().StringP("config", "c", "", "config file path (auto-discovered; creates ./qrypt.toml if none exists)")
	cmd.Flags().String("mount", "", "mount to add or reconnect (defaults to provider name)")
	cmd.Flags().Duration("timeout", 5*time.Minute, "maximum time to wait for login")
	return cmd
}

func loadLoginConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if os.IsNotExist(err) {
		return &config.Config{Version: "1"}, nil
	}
	return cfg, err
}

func loginMount(cfg *config.Config, provider, name string) (*config.MountConfig, error) {
	for i := range cfg.Mounts {
		if cfg.Mounts[i].Name != name {
			continue
		}
		if cfg.Mounts[i].Type != provider {
			return nil, fmt.Errorf("mount %q uses driver %q, not %q", name, cfg.Mounts[i].Type, provider)
		}
		return &cfg.Mounts[i], nil
	}
	cfg.Mounts = append(cfg.Mounts, config.MountConfig{Name: name, Type: provider})
	return &cfg.Mounts[len(cfg.Mounts)-1], nil
}

func saveLoginConfig(path, provider, name string, params map[string]string) error {
	// Re-read after scanning so unrelated settings edited while waiting survive.
	cfg, err := loadLoginConfig(path)
	if err != nil {
		return err
	}
	mount, err := loginMount(cfg, provider, name)
	if err != nil {
		return err
	}
	if mount.Params == nil {
		mount.Params = config.ParamMap{}
	}
	for key, value := range params {
		mount.Params[key] = value
	}
	if err := config.Validate(cfg); err != nil {
		return err
	}
	return config.Save(path, cfg)
}
