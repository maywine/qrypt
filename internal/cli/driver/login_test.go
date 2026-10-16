package driver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	cliruntime "github.com/yinzhenyu/qrypt/internal/cli/runtime"
	"github.com/yinzhenyu/qrypt/pkg/config"
	"github.com/yinzhenyu/qrypt/pkg/drive"
)

type loginStub struct {
	poll func(context.Context) (drive.WebLoginResult, error)
}

func (loginStub) Start(context.Context) (drive.WebLoginChallenge, error) {
	return drive.WebLoginChallenge{URL: "https://su.quark.cn/test", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (l loginStub) Poll(ctx context.Context) (drive.WebLoginResult, error) { return l.poll(ctx) }

func TestLoginCommandSavesConfirmedCredentialsOnly(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(fmt.Sprint(success), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "qrypt.toml")
			provider := t.Name()
			drive.Register(provider, func(params drive.Params) (drive.Driver, error) { return &drive.FakeDriver{}, nil }, drive.ParamDef{Name: "cookie", Required: true, Secret: true}, drive.ParamDef{Name: "root_path"})
			// The fake provider uses its own registry entry so tests cannot replace
			// the bundled Quark login factory used by other packages.
			cfg := &config.Config{Version: "1", Mounts: []config.MountConfig{{Name: "music", Type: provider, Params: config.ParamMap{"cookie": "old-cookie", "root_path": "/Music"}}}}
			if err := config.Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			drive.RegisterWebLogin(provider, func() drive.WebLogin {
				return loginStub{poll: func(context.Context) (drive.WebLoginResult, error) {
					if !success {
						return drive.WebLoginResult{}, errors.New("login rejected")
					}
					return drive.WebLoginResult{State: drive.WebLoginConfirmed, Params: map[string]string{"cookie": "new-secret-cookie"}}, nil
				}}
			})
			rt := cliruntime.TestRuntime{
				CommandConfigPathFn: func(*cobra.Command) (string, error) { return path, nil },
				ShutdownContextFn:   func(*cobra.Command) (context.Context, func()) { return context.Background(), func() {} },
			}
			cmd := NewLoginCmd(rt)
			if err := cmd.Flags().Set("mount", "music"); err != nil {
				t.Fatal(err)
			}
			var out, progress bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&progress)
			err = cmd.RunE(cmd, []string{provider})
			if (err == nil) != success {
				t.Fatalf("login success=%v: %v", success, err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !success && !bytes.Equal(before, after) {
				t.Fatal("failed login changed config")
			}
			if success {
				loaded, err := config.Load(path)
				if err != nil {
					t.Fatal(err)
				}
				if loaded.Mounts[0].Params["cookie"] != "new-secret-cookie" || loaded.Mounts[0].Params["root_path"] != "/Music" {
					t.Fatal("login did not preserve mount settings")
				}
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm()&0o077 != 0 {
					t.Fatalf("config permissions: %v, %v", info, err)
				}
			}
			if strings.Contains(out.String()+progress.String(), "new-secret-cookie") {
				t.Fatal("credential leaked to terminal")
			}
		})
	}
}
