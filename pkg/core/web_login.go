package core

import "github.com/yinzhenyu/qrypt/pkg/drive"

type WebLogin = drive.WebLogin
type WebLoginChallenge = drive.WebLoginChallenge
type WebLoginResult = drive.WebLoginResult

const (
	WebLoginWaiting   = drive.WebLoginWaiting
	WebLoginExpired   = drive.WebLoginExpired
	WebLoginConfirmed = drive.WebLoginConfirmed
)

// NewWebLogin starts a provider login without opening a core or a mount.
func NewWebLogin(provider string) (WebLogin, error) {
	return drive.NewWebLogin(provider)
}
