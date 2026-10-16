package driverutil

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yinzhenyu/qrypt/pkg/drive"
)

func TestBufferRedactsErrorBeforeMarkingSensitiveMasked(t *testing.T) {
	buffer := NewBuffer(1)
	buffer.Record(context.Background(), drive.MetricEvent{Error: "refresh_ui=refresh-secret&client_secret=client-secret\nCookie: first=one; second=cookie-secret"})
	events := buffer.Events(time.Time{})
	if len(events) != 1 || !events[0].SensitiveMasked {
		t.Fatal("missing masked event")
	}
	for _, secret := range []string{"refresh-secret", "client-secret", "cookie-secret"} {
		if strings.Contains(events[0].Error, secret) {
			t.Fatalf("metric leaked %q", secret)
		}
	}
}
