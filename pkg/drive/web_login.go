package drive

import (
	"context"
	"fmt"
	"time"
)

const (
	WebLoginWaiting   = "waiting"
	WebLoginExpired   = "expired"
	WebLoginConfirmed = "confirmed"
)

type WebLoginChallenge struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

type WebLoginResult struct {
	State string `json:"state"`
	// Params contains credentials only after confirmation. Hosts decide where
	// to store them; login never mutates an existing mount or config itself.
	Params map[string]string `json:"params,omitempty"`
}

// WebLogin is independent of an initialized driver so a host can obtain the
// credentials needed to create its first mount.
type WebLogin interface {
	Start(context.Context) (WebLoginChallenge, error)
	Poll(context.Context) (WebLoginResult, error)
}

var webLoginFactories = map[string]func() WebLogin{}

func RegisterWebLogin(name string, factory func() WebLogin) {
	registryMu.Lock()
	defer registryMu.Unlock()
	webLoginFactories[name] = factory
}

func NewWebLogin(name string) (WebLogin, error) {
	registryMu.RLock()
	factory := webLoginFactories[name]
	registryMu.RUnlock()
	if factory == nil {
		return nil, fmt.Errorf("%w: web login for %q", ErrUnsupported, name)
	}
	return factory(), nil
}
