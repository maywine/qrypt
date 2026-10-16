package quark

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yinzhenyu/qrypt/pkg/drive"
)

func loginResponse(req *http.Request, status int, body string, cookies ...string) *http.Response {
	header := make(http.Header)
	for _, cookie := range cookies {
		header.Add("Set-Cookie", cookie)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestWebLoginQRExchange(t *testing.T) {
	flow := NewWebLogin()
	polls := 0
	flow.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("User-Agent") != webLoginUserAgent || req.Header.Get("Referer") != "https://pan.quark.cn/" {
			t.Fatal("missing web login headers")
		}
		switch req.URL.Path {
		case "/cas/ajax/getTokenForQrcodeLogin":
			if req.URL.Query().Get("client_id") != "532" || len(req.URL.Query().Get("request_id")) != 36 {
				t.Fatalf("invalid login parameters: %v", req.URL.Query())
			}
			return loginResponse(req, 200, `{"status":2000000,"data":{"members":{"token":"token&other=1"}}}`, "cas_session=private; Path=/"), nil
		case "/cas/ajax/getServiceTicketByQrcodeToken":
			if req.URL.Query().Get("token") != "token&other=1" {
				t.Fatal("QR token changed")
			}
			polls++
			if polls == 1 {
				return loginResponse(req, 200, `{"status":50004001}`), nil
			}
			return loginResponse(req, 200, `{"status":2000000,"data":{"members":{"service_ticket":"ticket&secret=1"}}}`), nil
		case "/account/info":
			if req.URL.Query().Get("st") != "ticket&secret=1" || req.URL.Query().Get("lw") != "scan" {
				t.Fatal("service ticket changed")
			}
			return loginResponse(req, 200, `{}`, "__kps=account; Domain=.quark.cn; Path=/", "foreign=bad; Domain=.example.com; Path=/"), nil
		case "/1/clouddrive/config":
			if req.Header.Get("Cookie") != "__kps=account" {
				t.Fatalf("bootstrap cookie = %q", req.Header.Get("Cookie"))
			}
			return loginResponse(req, 200, `{}`, "__puus=session; Domain=.quark.cn; Path=/"), nil
		case "/1/clouddrive/file/sort":
			if req.URL.Host != "drive-pc.quark.cn" || !strings.Contains(req.Header.Get("Cookie"), "__puus=session") {
				t.Fatal("session was not validated with the PC API")
			}
			return loginResponse(req, 200, `{"status":200,"code":0,"data":{"list":[]}}`), nil
		default:
			t.Fatalf("unexpected request: %s", req.URL.Path)
			return nil, nil
		}
	})
	challenge, err := flow.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(challenge.URL)
	if err != nil || u.Query().Get("token") != "token&other=1" || u.Query().Get("other") != "" {
		t.Fatalf("QR query was not encoded: %q", challenge.URL)
	}
	result, err := flow.Poll(context.Background())
	if err != nil || result.State != drive.WebLoginWaiting || result.Params != nil {
		t.Fatalf("waiting = %+v, %v", result, err)
	}
	result, err = flow.Poll(context.Background())
	if err != nil || result.State != drive.WebLoginConfirmed {
		t.Fatalf("confirmed = %+v, %v", result, err)
	}
	cookie := result.Params["cookie"]
	if !strings.Contains(cookie, "__kps=account") || !strings.Contains(cookie, "__puus=session") || strings.Contains(cookie, "foreign") || strings.Contains(cookie, "cas_session") {
		t.Fatalf("exported wrong cookies: %q", cookie)
	}
	if _, err := flow.Poll(context.Background()); err == nil {
		t.Fatal("confirmed credentials were delivered twice")
	}
}

func TestWebLoginRejectsInvalidResponsesWithoutSecrets(t *testing.T) {
	for _, test := range []struct {
		name           string
		status         int
		body           string
		transportError bool
	}{
		{"missing token", 200, `{"status":2000000,"data":{"members":{}}}`, false},
		{"unexpected status", 200, `{"status":9999,"message":"secret-ticket"}`, false},
		{"malformed", 200, `secret-ticket`, false},
		{"rate limit", 429, `secret-ticket`, false},
		{"server error", 503, `secret-ticket`, false},
		{"redirect", 302, `secret-ticket`, false},
		{"network", 0, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := NewWebLogin()
			calls := 0
			flow.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if test.transportError {
					return nil, errors.New("connection failed with secret-ticket")
				}
				resp := loginResponse(req, test.status, test.body)
				resp.Header.Set("Location", "https://attacker.example/?ticket=secret-ticket")
				return resp, nil
			})
			_, err := flow.Start(context.Background())
			if err == nil || strings.Contains(err.Error(), "secret-ticket") || calls != 1 {
				t.Fatalf("unsafe error = %v, calls = %d", err, calls)
			}
			if test.status == 429 && !errors.Is(err, drive.ErrRateLimit) {
				t.Fatalf("rate limit classification = %v", err)
			}
			if test.transportError && drive.ErrorCategory(err) != drive.ErrorCategoryNetwork {
				t.Fatalf("network failure misclassified as %q", drive.ErrorCategory(err))
			}
			if test.status == 503 && drive.ErrorCategory(err) != drive.ErrorCategoryRemote5xx {
				t.Fatalf("server failure misclassified as %q", drive.ErrorCategory(err))
			}
		})
	}
}

func TestWebLoginExpiredAndRejectedSessions(t *testing.T) {
	for _, code := range []int{50004002, 50004003, 50004004} {
		flow := NewWebLogin()
		flow.token = "secret-token"
		flow.expiresAt = time.Now().Add(time.Minute)
		flow.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return loginResponse(req, 200, strings.ReplaceAll(`{"status":CODE}`, "CODE", fmt.Sprint(code))), nil
		})
		result, err := flow.Poll(context.Background())
		if err != nil || result.State != drive.WebLoginExpired || result.Params != nil {
			t.Fatalf("expired = %+v, %v", result, err)
		}
	}
	flow := NewWebLogin()
	flow.token = "secret-token"
	flow.expiresAt = time.Now().Add(time.Minute)
	flow.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "getServiceTicket") {
			return loginResponse(req, 200, `{"status":2000000,"data":{"members":{"service_ticket":"secret-ticket"}}}`), nil
		}
		return loginResponse(req, 200, `{"status":401,"message":"secret-cookie"}`), nil
	})
	result, err := flow.Poll(context.Background())
	if !errors.Is(err, drive.ErrAuth) || result.Params != nil || strings.Contains(err.Error(), "secret-cookie") {
		t.Fatalf("rejected = %+v, %v", result, err)
	}
}

func TestDownloadCookieScopeAndRedirects(t *testing.T) {
	client := newClient("__puus=secret", clientOptions{})
	for _, rawURL := range []string{
		"http://cdn.quark.cn/file", "https://quark.cn.attacker.example/file",
		"https://notquark.cn/file", "https://127.0.0.1/file", "https://user:password@cdn.quark.cn/file",
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
		if _, err := client.doDownload(req, ""); err == nil || req.Header.Get("Cookie") != "" {
			t.Fatalf("cookie allowed for %s", rawURL)
		}
	}
	calls := 0
	client.downloadClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		resp := loginResponse(req, 302, "")
		resp.Header.Set("Location", "https://attacker.example/collect")
		return resp, nil
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.quark.cn/file", nil)
	resp, err := client.doDownload(req, "")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || calls != 1 {
		t.Fatalf("redirect escaped cookie scope: calls=%d err=%v", calls, err)
	}
}

func TestCookieStateIsBoundToConfiguredLogin(t *testing.T) {
	store := drive.NewFileStateStore(filepath.Join(t.TempDir(), "driver"))
	old := New("__puus=old-login", Options{})
	old.InstallStateStore(store)
	old.saveUpdatedCookie("__puus=rotated-old")
	same := New("__puus=old-login", Options{})
	same.InstallStateStore(store)
	same.loadCookieState()
	if same.cl.cookieValue() != "__puus=rotated-old" {
		t.Fatal("same login lost its rotated cookie")
	}
	other := New("__puus=new-login", Options{})
	other.InstallStateStore(store)
	other.loadCookieState()
	if other.cl.cookieValue() != "__puus=new-login" || other.cookieSource != "config" {
		t.Fatal("new login restored credentials from the old account")
	}
}

func TestDownloadTransportErrorsOmitSignedURL(t *testing.T) {
	client := newClient("__puus=secret", clientOptions{})
	client.downloadClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, &net.DNSError{Name: req.URL.Hostname(), Err: "no such host"}
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.quark.cn/file?signature=secret-signature", nil)
	_, err := client.doDownload(req, "")
	var dnsErr *net.DNSError
	if err == nil || strings.Contains(err.Error(), "secret-signature") || !errors.As(err, &dnsErr) {
		t.Fatalf("unsafe transport error: %v", err)
	}
}
