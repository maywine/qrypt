package mobile

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yinzhenyu/qrypt/pkg/core"
)

type webLoginSession struct {
	flow   core.WebLogin
	ctx    context.Context
	cancel context.CancelFunc
	timer  *time.Timer
}

var webLogins = struct {
	sync.Mutex
	sessions map[string]*webLoginSession
}{sessions: map[string]*webLoginSession{}}

// StartWebLoginJSON obtains a QR challenge before any core is opened. The
// returned login_id is transient; render url as a QR code in the host app.
func StartWebLoginJSON(provider string, deadlineMS int) string {
	flow, err := core.NewWebLogin(provider)
	if err != nil {
		return resultJSON(nil, err)
	}
	ctx, cancel := core.TimeoutContext(deadlineMS)
	defer cancel()
	challenge, err := flow.Start(ctx)
	if err != nil {
		return resultJSON(nil, err)
	}
	id, err := newID()
	if err != nil {
		return resultJSON(nil, err)
	}
	loginCtx, loginCancel := context.WithDeadline(context.Background(), challenge.ExpiresAt)
	s := &webLoginSession{flow: flow, ctx: loginCtx, cancel: loginCancel}
	webLogins.Lock()
	webLogins.sessions[id] = s
	s.timer = time.AfterFunc(time.Until(challenge.ExpiresAt), func() { closeWebLogin(id) })
	webLogins.Unlock()
	return resultJSON(struct {
		LoginID string `json:"login_id"`
		core.WebLoginChallenge
	}{LoginID: id, WebLoginChallenge: challenge}, nil)
}

// PollWebLoginJSON returns waiting, expired, or confirmed. Only confirmed
// includes secret driver params. The app owns their secure storage and any
// explicit config update; qrypt never logs or automatically saves them.
func PollWebLoginJSON(loginID string, deadlineMS int) string {
	webLogins.Lock()
	s := webLogins.sessions[loginID]
	webLogins.Unlock()
	if s == nil {
		return resultJSON(nil, fmt.Errorf("mobile: unknown or expired web login"))
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if deadlineMS > 0 {
		ctx, cancel = context.WithTimeout(s.ctx, time.Duration(deadlineMS)*time.Millisecond)
	} else {
		ctx, cancel = context.WithCancel(s.ctx)
	}
	defer cancel()
	result, err := s.flow.Poll(ctx)
	if ctx.Err() != nil {
		return resultJSON(nil, ctx.Err())
	}
	if err != nil {
		return resultJSON(nil, err)
	}
	if result.State == core.WebLoginConfirmed || result.State == core.WebLoginExpired {
		closeWebLogin(loginID)
	}
	return resultJSON(result, nil)
}

// CloseWebLoginJSON cancels in-flight polling and discards this login attempt.
func CloseWebLoginJSON(loginID string) string {
	closeWebLogin(loginID)
	return resultJSON(true, nil)
}

func closeWebLogin(id string) {
	webLogins.Lock()
	s := webLogins.sessions[id]
	delete(webLogins.sessions, id)
	webLogins.Unlock()
	if s != nil {
		s.cancel()
		s.timer.Stop()
	}
}
