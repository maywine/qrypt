package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yinzhenyu/qrypt/pkg/control"
	"github.com/yinzhenyu/qrypt/pkg/vfs/diagnostics"
)

type debugAuthSource struct{}

func (debugAuthSource) DebugSnapshot() diagnostics.DebugSnapshot {
	return diagnostics.DebugSnapshot{}
}

func TestDebugTCPAuthentication(t *testing.T) {
	const token = "test-debug-token-at-least-32-characters"
	server, err := control.NewServer("127.0.0.1:0", debugAuthSource{})
	if err != nil {
		t.Fatal(err)
	}
	server.SetAuthToken(token)
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(context.Background()) })
	listen := strings.TrimPrefix(server.ListenAddress(), "tcp:")
	configFile := filepath.Join(t.TempDir(), "qrypt.toml")
	if err := os.WriteFile(configFile, fmt.Appendf(nil, "[debug]\nenabled = true\nlisten = %q\ntoken = %q\n", listen, token), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--config", configFile},
		{"--url", "http://" + listen, "--config", configFile},
		{"--url", "http://" + listen, "--token-file", tokenFile},
	} {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(append([]string{"debug", "raw", "health"}, args...))
		if err := root.Execute(); err != nil {
			t.Fatalf("debug raw %v: %v", args, err)
		}
		if !strings.Contains(out.String(), `"ok": true`) || strings.Contains(out.String(), token) {
			t.Fatalf("unexpected health response: %s", &out)
		}
	}
}
