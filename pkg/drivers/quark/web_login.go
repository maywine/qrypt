package quark

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yinzhenyu/qrypt/pkg/drive"
	"golang.org/x/net/publicsuffix"
)

const webLoginLifetime = 5 * time.Minute

func init() {
	drive.RegisterWebLogin("quark", func() drive.WebLogin { return NewWebLogin() })
}

// WebLogin implements Quark's web QR flow, as used by Cruise-Tune. Tokens,
// service tickets and the cookie jar belong to one in-memory login attempt.
type WebLogin struct {
	mu         sync.Mutex
	httpClient *http.Client
	authURL    string
	accountURL string
	configURL  string
	driveURL   string
	token      string
	expiresAt  time.Time
}

func NewWebLogin() *WebLogin {
	client := newHTTPClient(30 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &WebLogin{
		httpClient: client,
		authURL:    "https://uop.quark.cn/cas/ajax/",
		accountURL: "https://pan.quark.cn/account/info",
		configURL:  defaultBaseURL + "/config",
		driveURL:   defaultDownloadBaseURL,
	}
}

func (l *WebLogin) Start(ctx context.Context) (drive.WebLoginChallenge, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.token = ""
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return drive.WebLoginChallenge{}, err
	}
	l.httpClient.Jar = jar
	params := loginParams()
	var reply webLoginReply
	if err := l.get(ctx, l.authURL+"getTokenForQrcodeLogin", params, &reply); err != nil {
		return drive.WebLoginChallenge{}, err
	}
	if reply.Status != 2000000 || strings.TrimSpace(reply.Data.Members.Token) == "" {
		return drive.WebLoginChallenge{}, fmt.Errorf("quark: web login did not return a QR token")
	}
	l.token = reply.Data.Members.Token
	l.expiresAt = time.Now().Add(webLoginLifetime)
	u, _ := url.Parse("https://su.quark.cn/4_eMHBJ")
	u.RawQuery = url.Values{
		"token":        {l.token},
		"client_id":    {"532"},
		"ssb":          {"weblogin"},
		"uc_param_str": {""},
		"uc_biz_str":   {"S:custom|OPT:SAREA@0|OPT:IMMERSIVE@1|OPT:BACK_BTN_STYLE@0"},
	}.Encode()
	return drive.WebLoginChallenge{URL: u.String(), ExpiresAt: l.expiresAt}, nil
}

func (l *WebLogin) Poll(ctx context.Context) (drive.WebLoginResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.expiresAt.IsZero() {
		return drive.WebLoginResult{}, fmt.Errorf("quark: web login has not started")
	}
	if !time.Now().Before(l.expiresAt) {
		l.token = ""
		return drive.WebLoginResult{State: drive.WebLoginExpired}, nil
	}
	if l.token == "" {
		return drive.WebLoginResult{}, fmt.Errorf("quark: web login has already finished")
	}
	params := loginParams()
	params.Set("token", l.token)
	var reply webLoginReply
	if err := l.get(ctx, l.authURL+"getServiceTicketByQrcodeToken", params, &reply); err != nil {
		return drive.WebLoginResult{}, err
	}
	switch reply.Status {
	case 50004001:
		return drive.WebLoginResult{State: drive.WebLoginWaiting}, nil
	case 50004002, 50004003, 50004004:
		l.token = ""
		l.expiresAt = time.Now()
		return drive.WebLoginResult{State: drive.WebLoginExpired}, nil
	case 2000000:
		if reply.Data.Members.ServiceTicket == "" {
			return drive.WebLoginResult{State: drive.WebLoginWaiting}, nil
		}
	default:
		return drive.WebLoginResult{}, fmt.Errorf("quark: web login rejected (status %d)", reply.Status)
	}
	cookie, err := l.exchange(ctx, reply.Data.Members.ServiceTicket)
	if err != nil {
		return drive.WebLoginResult{}, err
	}
	l.token = ""
	return drive.WebLoginResult{State: drive.WebLoginConfirmed, Params: map[string]string{"cookie": cookie}}, nil
}

func (l *WebLogin) exchange(ctx context.Context, ticket string) (string, error) {
	for _, step := range []struct {
		url    string
		params url.Values
	}{
		{l.accountURL, url.Values{"st": {ticket}, "lw": {"scan"}}},
		{l.configURL, url.Values{"pr": {"ucpro"}, "fr": {"pc"}}},
		{l.driveURL + "/file/sort", url.Values{"pr": {"ucpro"}, "fr": {"pc"}, "pdir_fid": {"0"}, "_size": {"1"}}},
	} {
		var reply webLoginReply
		if err := l.get(ctx, step.url, step.params, &reply); err != nil {
			return "", err
		}
		if reply.Code != 0 || reply.Status >= 400 {
			return "", fmt.Errorf("%w: quark web session rejected", drive.ErrAuth)
		}
		if step.url == l.driveURL+"/file/sort" && reply.Status != 200 {
			return "", fmt.Errorf("%w: quark web session validation failed", drive.ErrAuth)
		}
	}
	u, _ := url.Parse(l.driveURL + "/file/sort")
	cookies := l.httpClient.Jar.Cookies(u)
	var parts []string
	valid := false
	for _, cookie := range cookies {
		parts = append(parts, cookie.Name+"="+cookie.Value)
		if cookie.Value != "" && (cookie.Name == "__puus" || cookie.Name == "__pus" || cookie.Name == "__kps") {
			valid = true
		}
	}
	if !valid {
		return "", fmt.Errorf("%w: quark web login returned no session cookie", drive.ErrAuth)
	}
	return strings.Join(parts, "; "), nil
}

type webLoginReply struct {
	Status int `json:"status"`
	Code   int `json:"code"`
	Data   struct {
		Members struct {
			Token         string `json:"token"`
			ServiceTicket string `json:"service_ticket"`
		} `json:"members"`
	} `json:"data"`
}

func loginParams() url.Values {
	var id [16]byte
	_, _ = rand.Read(id[:])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return url.Values{
		"client_id":  {"532"},
		"v":          {"1.2"},
		"request_id": {fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])},
	}
}

func (l *WebLogin) get(ctx context.Context, endpoint string, params url.Values, reply *webLoginReply) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("quark: invalid web login endpoint")
	}
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("quark: cannot create web login request")
	}
	req.Header.Set("User-Agent", webLoginUserAgent)
	req.Header.Set("Referer", defaultReferer+"/")
	req.Header.Set("Accept", "application/json")
	resp, err := l.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// url.Error includes the QR token or service ticket in its URL.
		return fmt.Errorf("quark: web service connection lost")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("%w: quark web login", drive.ErrRateLimit)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("quark: web service HTTP status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(reply); err != nil {
		return fmt.Errorf("quark: invalid web service response")
	}
	return nil
}
