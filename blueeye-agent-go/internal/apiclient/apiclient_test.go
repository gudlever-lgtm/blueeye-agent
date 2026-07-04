package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func statusServer(code int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
}

func TestExplicitStatusCodes(t *testing.T) {
	cases := []struct {
		status int
		want   Code
	}{
		{200, ""},
		{201, ""},
		{400, BadRequest},
		{401, TokenRejected},
		{404, NotFound},
		{500, ServerError},
		{503, ServerError},
		{418, HTTPError},
	}
	for _, tc := range cases {
		srv := statusServer(tc.status, `{}`)
		c := New(srv.URL, "tok", srv.Client())
		err := c.PostResults(context.Background(), []any{map[string]any{"ok": true}})
		srv.Close()
		if tc.want == "" {
			if err != nil {
				t.Errorf("status %d: unexpected error %v", tc.status, err)
			}
			continue
		}
		var ae *Error
		if !errors.As(err, &ae) {
			t.Errorf("status %d: want *Error, got %v", tc.status, err)
			continue
		}
		if ae.Code != tc.want {
			t.Errorf("status %d: code = %s, want %s", tc.status, ae.Code, tc.want)
		}
		if ae.Status != tc.status {
			t.Errorf("status %d: Error.Status = %d", tc.status, ae.Status)
		}
	}
}

func TestEnrollSuccessAndAuthHeader(t *testing.T) {
	var gotAuth, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"agentId":7,"token":"abc"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "tok", srv.Client())
	res, err := c.Enroll(context.Background(), EnrollRequest{Code: "c", Hostname: "h", Platform: "linux", Arch: "x64"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.AgentID != 7 || res.Token != "abc" {
		t.Fatalf("enroll response = %+v", res)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization header = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
}

func TestGetDefinitions404And500(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   Code
	}{{404, NotFound}, {500, ServerError}} {
		srv := statusServer(tc.status, `{"error":"x"}`)
		c := New(srv.URL, "tok", srv.Client())
		_, err := c.GetDefinitions(context.Background())
		srv.Close()
		var ae *Error
		if !errors.As(err, &ae) || ae.Code != tc.want {
			t.Errorf("GetDefinitions status %d: err = %v, want code %s", tc.status, err, tc.want)
		}
	}
}

func TestGetConfigSuccess(t *testing.T) {
	srv := statusServer(200, `{"agentId":1,"monitorConfig":{"source":"proc"}}`)
	defer srv.Close()
	c := New(srv.URL, "tok", srv.Client())
	res, err := c.GetConfig(context.Background())
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if res.AgentID != 1 || string(res.MonitorConfig) != `{"source":"proc"}` {
		t.Fatalf("config = %+v", res)
	}
}

func TestTransportError(t *testing.T) {
	c := New("http://127.0.0.1:1", "tok", &http.Client{})
	err := c.PostResults(context.Background(), nil)
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != Transport {
		t.Fatalf("want Transport error, got %v", err)
	}
}
