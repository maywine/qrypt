package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	_ "github.com/yinzhenyu/qrypt/pkg/drivers/all"
)

// TestConfigShowMasksSecrets is the end-to-end guarantee: running
// `qrypt config show` on a config with driver secrets must never print the
// plaintext, while non-secret parameters stay readable.
func TestConfigShowMasksSecrets(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "qrypt.toml")
	content := `# qrypt config
[[mounts]]
name = "local"
type = "localfs"

[mounts.params]
root_path = "/tmp/nothing-here"

[[mounts]]
name = "quark"
type = "quark"

[mounts.params]
cookie = "top-secret-quark-cookie"
root_path = "/quark"
base_url = "https://example.com"

[[mounts]]
name = "another"
type = "quark"

[mounts.params]
cookie = ""
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewShowCmd(newTestRuntime())
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Flags().Set("config", configPath); err != nil {
		t.Fatal(err)
	}
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	// The secret plaintext must never appear.
	if strings.Contains(got, "top-secret-quark-cookie") {
		t.Fatalf("config show leaked a secret:\n%s", got)
	}
	// The masked form appears, including the empty-secret case.
	if !strings.Contains(got, `cookie = "******"`) {
		t.Fatalf("config show did not mask cookie:\n%s", got)
	}
	// Non-secret parameters are readable.
	if !strings.Contains(got, `root_path = "/quark"`) {
		t.Fatalf("config show hid a non-secret parameter:\n%s", got)
	}
	if !strings.Contains(got, `base_url = "https://example.com"`) {
		t.Fatalf("config show hid base_url:\n%s", got)
	}
}

func TestConfigShowMasksTOMLValues(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{
			name: "debug token",
			input: `[debug]
enabled = true
listen = "127.0.0.1:19090"
token = "audit-secret-debug-token-0123456789"
`,
			want: `[debug]
enabled = true
listen = "127.0.0.1:19090"
token = "******"
`,
		},
		{
			name:  "quoted key",
			input: `encryption."password" = "audit-secret-password"`,
			want:  `encryption.password = "******"`,
		},
		{
			name:  "escaped key and value",
			input: `encryption."\u0070assword" = "audit-secret-\u0070assword"`,
			want:  `encryption.password = "******"`,
		},
		{
			name:  "case insensitive config field",
			input: `Encryption.Password = "audit-secret-password"`,
			want:  `Encryption.Password = "******"`,
		},
		{
			name:  "unicode case folding",
			input: `encryption."paſſword" = "audit-secret-password"`,
			want:  `encryption."paſſword" = "******"`,
		},
		{
			name: "multiline private key",
			input: `[[mounts]]
name = "sftp"
type = "sftp"
[mounts.params]
private_key = """
-----BEGIN OPENSSH PRIVATE KEY-----
audit-secret-key-body
-----END OPENSSH PRIVATE KEY-----
"""
`,
			want: `[[mounts]]
name = "sftp"
type = "sftp"
[mounts.params]
private_key = "******"
`,
		},
		{
			name: "multiline literal password",
			input: `[encryption]
password = '''
audit-secret-line-one
audit-secret-line-two
'''
salt = ""
`,
			want: `encryption = {password = "******", salt = ""}`,
		},
		{
			name: "inline params and empty secrets",
			input: `[[mounts]]
name = "quark"
type = "quark"
params = {cookie = "audit-secret-cookie", root_path = "/keep", retry = 2, enabled = true}
[[mounts]]
name = "other"
type = "quark"
params = {cookie = ""}
`,
			want: `[[mounts]]
name = "quark"
type = "quark"
params = {cookie = "******", root_path = "/keep", retry = 2, enabled = true}
[[mounts]]
name = "other"
type = "quark"
params = {cookie = ""}
`,
		},
		{
			name:  "inline mount array",
			input: `mounts = [{name = "quark", type = "quark", params = {cookie = "audit-secret-cookie"}}]`,
			want: `[[mounts]]
name = "quark"
type = "quark"
params = {cookie = "******"}
`,
		},
		{
			name: "nested tables and unknown settings",
			input: `defaults.encryption = {password = "audit-secret-password", salt = "audit-secret-salt"}
extra = {label = "keep", nested = [{cookie = "audit-secret-cookie"}]}
`,
			want: `defaults.encryption = {password = "******", salt = "******"}
[extra]
label = "keep"
[[extra.nested]]
cookie = "******"
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "qrypt.toml")
			if err := os.WriteFile(configPath, []byte(tc.input), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := NewShowCmd(newTestRuntime())
			var out bytes.Buffer
			cmd.SetOut(&out)
			if err := cmd.Flags().Set("config", configPath); err != nil {
				t.Fatal(err)
			}
			if err := cmd.RunE(cmd, nil); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "audit-secret") || strings.Contains(out.String(), "PRIVATE KEY") {
				t.Fatalf("config show leaked credentials: %s", out.String())
			}
			var got, want map[string]any
			if err := toml.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatalf("output is not valid TOML: %v", err)
			}
			if err := toml.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("config show = %#v, want %#v", got, want)
			}
		})
	}
}

func TestConfigShowParseErrorDoesNotLeakSecrets(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "qrypt.toml")
	if err := os.WriteFile(configPath, []byte("[debug]\ntoken = audit-secret-unquoted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewShowCmd(newTestRuntime())
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Flags().Set("config", configPath); err != nil {
		t.Fatal(err)
	}
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("config show accepted invalid TOML")
	}
	if strings.Contains(err.Error(), "audit-secret") || out.Len() != 0 {
		t.Fatalf("config show leaked invalid input: output=%q err=%v", out.String(), err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("parse error lost its location: %v", err)
	}
}
