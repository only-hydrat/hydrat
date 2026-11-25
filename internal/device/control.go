package device

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
)

// Control is served only over OS-authorized local IPC. Connect manages the
// lifetime of the platform tunnel and returns after its routes are removed.
type Control struct {
	app     *App
	mux     *http.ServeMux
	root    context.Context
	connect func(context.Context) error

	mu         sync.Mutex
	closed     bool
	cancel     context.CancelFunc
	done       chan struct{}
	connection string
}

type ControlStatus struct {
	Status
	Connection string
}

func NewControl(ctx context.Context, app *App, connect func(context.Context) error) *Control {
	control := &Control{app: app, root: ctx, connect: connect, mux: http.NewServeMux(), connection: "disconnected"}
	control.mux.HandleFunc("GET /status", control.status)
	control.mux.HandleFunc("POST /sources", control.importSource)
	control.mux.HandleFunc("POST /connection", control.start)
	control.mux.HandleFunc("DELETE /connection", control.stop)
	return control
}

func (control *Control) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	control.mux.ServeHTTP(response, request)
}

func (control *Control) Snapshot(ctx context.Context) (ControlStatus, error) {
	control.mu.Lock()
	connection := control.connection
	control.mu.Unlock()
	status, err := control.app.Status(ctx)
	return ControlStatus{Status: status, Connection: connection}, err
}

func (control *Control) status(response http.ResponseWriter, request *http.Request) {
	status, err := control.Snapshot(request.Context())
	if err != nil {
		http.Error(response, "could not read local state", http.StatusInternalServerError)
		return
	}
	writeJSON(response, status)
}

func (control *Control) importSource(response http.ResponseWriter, request *http.Request) {
	body := http.MaxBytesReader(response, request.Body, maxImportSize)
	input, err := io.ReadAll(body)
	if err != nil {
		http.Error(response, "could not read subscription input", http.StatusBadRequest)
		return
	}
	report, err := control.app.Import(request.Context(), string(input))
	if err != nil {
		http.Error(response, "could not import local sources", http.StatusBadRequest)
		return
	}
	writeJSON(response, report)
}

var (
	errControlStopping = errors.New("control service is stopping")
	errTunnelActive    = errors.New("a tunnel session is still active")
)

func (control *Control) start(response http.ResponseWriter, _ *http.Request) {
	if err := control.Connect(); err != nil {
		code := http.StatusConflict
		if errors.Is(err, errControlStopping) {
			code = http.StatusServiceUnavailable
		}
		http.Error(response, err.Error(), code)
		return
	}
	response.WriteHeader(http.StatusAccepted)
}

func (control *Control) Connect() error {
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.closed || control.root.Err() != nil {
		return errControlStopping
	}
	if control.done != nil {
		return errTunnelActive
	}
	ctx, cancel := context.WithCancel(control.root)
	control.cancel = cancel
	control.done = make(chan struct{})
	control.connection = "requested"
	go control.run(ctx)
	return nil
}

func (control *Control) run(ctx context.Context) {
	err := control.connect(ctx)
	control.mu.Lock()
	defer control.mu.Unlock()
	control.cancel()
	control.connection = "disconnected"
	if err != nil && !control.closed {
		control.connection = "failed"
		log.Printf("device tunnel: %v", err)
	}
	close(control.done)
	control.done, control.cancel = nil, nil
}

func (control *Control) stop(response http.ResponseWriter, _ *http.Request) {
	control.Disconnect()
	response.WriteHeader(http.StatusAccepted)
}

func (control *Control) Disconnect() {
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.cancel != nil {
		control.connection = "stopping"
		control.cancel()
	}
}

func (control *Control) Close(ctx context.Context) error {
	control.mu.Lock()
	control.closed = true
	done := control.done
	if control.cancel != nil {
		control.cancel()
	}
	control.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func writeJSON(response http.ResponseWriter, value any) {
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(value)
}
