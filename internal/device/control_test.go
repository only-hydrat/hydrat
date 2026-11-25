package device

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestControlKeepsSessionExclusiveUntilTheTunnelHasClosed(t *testing.T) {
	app, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stopping := make(chan struct{})
	cleanup := make(chan struct{})
	control := NewControl(ctx, app, func(session context.Context) error {
		<-session.Done()
		close(stopping)
		<-cleanup
		return nil
	})
	request := func(method string) int {
		response := httptest.NewRecorder()
		control.ServeHTTP(response, httptest.NewRequest(method, "/connection", nil))
		return response.Code
	}
	if result := request(http.MethodPost); result != http.StatusAccepted {
		t.Fatalf("connect = %d", result)
	}
	if result := request(http.MethodDelete); result != http.StatusAccepted {
		t.Fatalf("disconnect = %d", result)
	}
	select {
	case <-stopping:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if result := request(http.MethodPost); result != http.StatusConflict {
		t.Fatalf("connect before cleanup = %d", result)
	}
	close(cleanup)
	if err := control.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
