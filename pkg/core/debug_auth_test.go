package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yinzhenyu/qrypt/pkg/config"
	"github.com/yinzhenyu/qrypt/pkg/control"
)

func TestCoreDebugServerUsesConfiguredToken(t *testing.T) {
	const token = "test-debug-token-at-least-32-characters"
	for _, enabled := range []bool{false, true} {
		tmp := t.TempDir()
		remote := filepath.Join(tmp, "remote")
		if err := os.MkdirAll(remote, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{
			Debug:  config.DebugConfig{Enabled: enabled, Listen: "127.0.0.1:0", Token: token},
			Mounts: []config.MountConfig{{Name: "local", Type: "localfs", Params: config.ParamMap{"root_path": remote}}},
		}
		file := filepath.Join(tmp, "qrypt.toml")
		if err := config.Save(file, cfg); err != nil {
			t.Fatal(err)
		}
		c, err := Open(context.Background(), Options{ConfigPath: file, Runtime: testRuntimeLayout(tmp)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		if !enabled {
			if err := c.StartDebugServer(context.Background(), cfg.Debug.Listen); err != nil {
				t.Fatal(err)
			}
		}
		if c.debugServer == nil {
			t.Fatal("configured debug server did not start")
		}
		client, err := control.NewClient("http://" + strings.TrimPrefix(c.debugServer.ListenAddress(), "tcp:"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Get(context.Background(), "/v1/health"); err == nil {
			t.Fatal("core debug API allowed unauthenticated access")
		}
		client.SetAuthToken(token)
		if _, err := client.Get(context.Background(), "/v1/health"); err != nil {
			t.Fatal(err)
		}
	}
}
