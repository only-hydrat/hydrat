package i2p

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSupervisorLeasesReleaseExpireAndStop(t *testing.T) {
	router := &testRouter{ready: true}
	r := NewRuntime(router, time.Hour)
	handler, expire := supervisorHandler(r)
	call := func(method, path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	acquire := func() string {
		t.Helper()
		w := call("POST", "/lease")
		var v struct{ ID string }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.ID == "" {
			t.Fatal(w.Code, w.Body.String())
		}
		return v.ID
	}
	id := acquire()
	if s := r.Status(); s.Streams != 1 || router.starts != 1 {
		t.Fatal(s)
	}
	if w := call("PUT", "/lease/"+id); w.Code != 204 {
		t.Fatal(w.Code)
	}
	expire(time.Now().Add(46 * time.Second))
	if s := r.Status(); s.Streams != 0 {
		t.Fatal("orphan lease still pins router", s)
	}
	if w := call("PUT", "/lease/"+id); w.Code != 404 {
		t.Fatal("expired lease renewed", w.Code)
	}
	call("DELETE", "/lease/"+id)
	if s := r.Status(); s.Streams != 0 {
		t.Fatal("double release", s)
	}
	acquire()
	id = acquire()
	if w := call("POST", "/stop"); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if s := r.Status(); s.State != "sleeping" || s.Streams != 0 || router.stops != 1 {
		t.Fatal(s)
	}
	if w := call("PUT", "/lease/"+id); w.Code != 404 {
		t.Fatal("stopped lease survived")
	}
	acquire()
	if router.starts != 2 || r.Status().Streams != 1 {
		t.Fatal("cannot wake after sleep")
	}
}
