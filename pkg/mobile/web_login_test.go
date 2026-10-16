package mobile

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yinzhenyu/qrypt/pkg/core"
	"github.com/yinzhenyu/qrypt/pkg/drive"
)

type testWebLogin struct {
	start func(context.Context) (drive.WebLoginChallenge, error)
	poll  func(context.Context) (drive.WebLoginResult, error)
}

func (l testWebLogin) Start(ctx context.Context) (drive.WebLoginChallenge, error) {
	return l.start(ctx)
}

func (l testWebLogin) Poll(ctx context.Context) (drive.WebLoginResult, error) {
	return l.poll(ctx)
}

func startTestWebLogin(t *testing.T, flow testWebLogin) string {
	t.Helper()
	drive.RegisterWebLogin(t.Name(), func() drive.WebLogin { return flow })
	var response struct {
		OK   bool `json:"ok"`
		Data struct {
			LoginID string `json:"login_id"`
			URL     string `json:"url"`
		} `json:"data"`
	}
	raw := StartWebLoginJSON(t.Name(), 1000)
	if err := json.Unmarshal([]byte(raw), &response); err != nil || !response.OK || response.Data.LoginID == "" || response.Data.URL == "" {
		t.Fatalf("start = %s, %v", raw, err)
	}
	t.Cleanup(func() { CloseWebLoginJSON(response.Data.LoginID) })
	return response.Data.LoginID
}

func TestWebLoginWithoutCoreAndConsumedCredentials(t *testing.T) {
	polls := 0
	id := startTestWebLogin(t, testWebLogin{
		start: func(context.Context) (drive.WebLoginChallenge, error) {
			return drive.WebLoginChallenge{URL: "https://su.quark.cn/qr", ExpiresAt: time.Now().Add(time.Minute)}, nil
		},
		poll: func(context.Context) (drive.WebLoginResult, error) {
			polls++
			if polls == 1 {
				return drive.WebLoginResult{State: drive.WebLoginWaiting}, nil
			}
			return drive.WebLoginResult{State: drive.WebLoginConfirmed, Params: map[string]string{"cookie": "__puus=secret"}}, nil
		},
	})
	if raw := PollWebLoginJSON(id, 1000); !strings.Contains(raw, `"state":"waiting"`) || strings.Contains(raw, "params") {
		t.Fatalf("waiting = %s", raw)
	}
	if raw := PollWebLoginJSON(id, 1000); !strings.Contains(raw, `"cookie":"__puus=secret"`) || !strings.Contains(raw, `"state":"confirmed"`) {
		t.Fatalf("confirmed = %s", raw)
	}
	if raw := PollWebLoginJSON(id, 1000); !strings.Contains(raw, `"ok":false`) || strings.Contains(raw, "__puus=secret") {
		t.Fatalf("credentials were delivered again: %s", raw)
	}
}

func TestCloseWebLoginCancelsPoll(t *testing.T) {
	started := make(chan struct{})
	id := startTestWebLogin(t, testWebLogin{
		start: func(context.Context) (drive.WebLoginChallenge, error) {
			return drive.WebLoginChallenge{URL: "https://su.quark.cn/qr", ExpiresAt: time.Now().Add(time.Minute)}, nil
		},
		poll: func(ctx context.Context) (drive.WebLoginResult, error) {
			close(started)
			<-ctx.Done()
			return drive.WebLoginResult{State: drive.WebLoginConfirmed, Params: map[string]string{"cookie": "must-not-escape"}}, nil
		},
	})
	done := make(chan string, 1)
	go func() { done <- PollWebLoginJSON(id, 0) }()
	<-started
	CloseWebLoginJSON(id)
	select {
	case raw := <-done:
		if strings.Contains(raw, "must-not-escape") || !strings.Contains(raw, string(core.ErrorCodeCancelled)) {
			t.Fatalf("cancelled = %s", raw)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not cancel polling")
	}
}

func TestWebLoginAutomaticallyExpires(t *testing.T) {
	id := startTestWebLogin(t, testWebLogin{
		start: func(context.Context) (drive.WebLoginChallenge, error) {
			return drive.WebLoginChallenge{URL: "https://su.quark.cn/qr", ExpiresAt: time.Now().Add(20 * time.Millisecond)}, nil
		},
	})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		webLogins.Lock()
		_, exists := webLogins.sessions[id]
		webLogins.Unlock()
		if !exists {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("expired login retained its session")
}
