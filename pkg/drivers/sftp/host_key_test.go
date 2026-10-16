package sftp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestHostKeyCallbackRejectsMissingKnownHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, file := range []string{"", filepath.Join(home, "missing")} {
		callback, err := New(Options{KnownHosts: file}).hostKeyCallback()
		if err == nil || callback != nil {
			t.Fatal("missing known_hosts did not fail closed")
		}
	}
}

func TestSFTPUsesDefaultKnownHosts(t *testing.T) {
	server := newMockSFTPServer(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	file := filepath.Join(home, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(server.knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	driver := New(Options{Address: server.listener.Addr().String(), Username: server.user, PrivateKey: server.keyPath, RootPath: server.root})
	if err := driver.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Drop(context.Background()) })
}

func TestSFTPRejectsUnknownAndChangedHostKeys(t *testing.T) {
	server := newMockSFTPServer(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1:1", server.listener.Addr().String()} {
		file := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(file, []byte(knownhosts.Line([]string{host}, signer.PublicKey())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		driver := New(Options{Address: server.listener.Addr().String(), Username: server.user, PrivateKey: server.keyPath, KnownHosts: file, RootPath: server.root})
		if err := driver.Init(context.Background()); err == nil {
			_ = driver.Drop(context.Background())
			t.Fatal("untrusted host key was accepted")
		}
	}
}
