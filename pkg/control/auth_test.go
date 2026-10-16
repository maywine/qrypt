package control

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTCPServerRequiresToken(t *testing.T) {
	for _, token := range []string{"", strings.Repeat("t", 31), strings.Repeat("t", 32) + "\n"} {
		server, err := NewServer("127.0.0.1:0", fakeSnapshotter{})
		if err != nil {
			t.Fatal(err)
		}
		server.SetAuthToken(token)
		if err := server.Start(context.Background()); err == nil {
			server.Close(context.Background())
			t.Fatal("TCP server started without a valid token")
		}
		if server.listener != nil {
			t.Fatal("failed authentication configuration opened a listener")
		}
	}
}

type authResetSnapshotter struct {
	fakeSnapshotter
	resets atomic.Int32
}

func (s *authResetSnapshotter) DebugReset(context.Context) error {
	s.resets.Add(1)
	return nil
}

func TestTCPServerAuthenticatesBeforeDispatch(t *testing.T) {
	const token = "test-debug-token-at-least-32-characters"
	source := &authResetSnapshotter{}
	server, err := NewServer("127.0.0.1:0", source)
	if err != nil {
		t.Fatal(err)
	}
	server.SetAuthToken(token)
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(context.Background()) })
	baseURL := "http://" + strings.TrimPrefix(server.ListenAddress(), "tcp:")

	for _, tc := range []struct {
		name, auth, host, origin string
		status                   int
	}{
		{name: "missing token", status: http.StatusUnauthorized},
		{name: "wrong token", auth: "Bearer " + strings.Repeat("x", 32), status: http.StatusUnauthorized},
		{name: "query token is not authentication", status: http.StatusUnauthorized},
		{name: "DNS rebinding Host", auth: "Bearer " + token, host: "attacker.example:19090", status: http.StatusForbidden},
		{name: "non-loopback Host", auth: "Bearer " + token, host: "192.0.2.1:19090", status: http.StatusForbidden},
		{name: "browser Origin", auth: "Bearer " + token, origin: "https://attacker.example", status: http.StatusForbidden},
		{name: "null Origin", auth: "Bearer " + token, origin: "null", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, endpoint := range []struct{ method, path string }{
				{http.MethodGet, "/v1/state"},
				{http.MethodPost, "/v1/debug/reset"},
			} {
				req, err := http.NewRequest(endpoint.method, baseURL+endpoint.path+"?token="+token, strings.NewReader("{}"))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "text/plain")
				if tc.auth != "" {
					req.Header.Set("Authorization", tc.auth)
				}
				if tc.origin != "" {
					req.Header.Set("Origin", tc.origin)
				}
				if tc.host != "" {
					req.Host = tc.host
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != tc.status {
					t.Fatalf("%s %s: status %d, want %d", endpoint.method, endpoint.path, resp.StatusCode, tc.status)
				}
				if strings.Contains(string(body), token) {
					t.Fatal("authentication response leaked token")
				}
			}
		})
	}
	if source.resets.Load() != 0 {
		t.Fatal("rejected request mutated debug state")
	}
	client, err := NewClient(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken(token)
	if _, err := client.Get(context.Background(), "/v1/health"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PostJSON(context.Background(), "/v1/debug/reset", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if source.resets.Load() != 1 {
		t.Fatal("authenticated reset was not dispatched")
	}
}

func TestClientDoesNotForwardTokenOnRedirect(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Store(true)
	}))
	defer target.Close()
	const token = "test-debug-token-at-least-32-characters"
	var authenticated atomic.Bool
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated.Store(r.Header.Get("Authorization") == "Bearer "+token)
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	client, err := NewClient(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken(token)
	if _, err := client.Get(context.Background(), "/v1/health"); err == nil {
		t.Fatal("redirect was accepted")
	}
	if !authenticated.Load() || redirected.Load() {
		t.Fatal("token was missing or redirected to another endpoint")
	}
}
