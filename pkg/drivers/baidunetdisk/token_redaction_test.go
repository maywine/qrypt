package baidunetdisk

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTokenTransportErrorDoesNotExposeCredentials(t *testing.T) {
	driver := New(Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := driver.requestToken(ctx, http.MethodGet, "https://api.example.com/token?refresh_ui=refresh-secret&client_secret=client-secret", nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("transport error lost cancellation: %v", err)
	}
	for _, secret := range []string{"refresh-secret", "client-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("transport error leaked %q", secret)
		}
		for _, event := range driver.metrics.Events(time.Time{}) {
			if strings.Contains(event.Error, secret) {
				t.Fatalf("transport metric leaked %q", secret)
			}
		}
	}
}
