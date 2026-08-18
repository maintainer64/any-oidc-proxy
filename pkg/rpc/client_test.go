package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newRPCServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestCallSuccess(t *testing.T) {
	var gotBody map[string]any
	var gotAuth string
	srv := newRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api_jsonrpc.php" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &gotBody); err != nil {
			t.Fatalf("bad request json: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","result":[{"userid":"1","username":"alice"}],"id":1}`))
	})

	c := NewRPCClient(srv.URL+"/api_jsonrpc.php", WithHeader("Authorization", "Bearer tok"))
	var result []struct {
		UserID   string `json:"userid"`
		Username string `json:"username"`
	}
	err := c.Call(context.Background(), "user.get", map[string]any{"output": "extend"}, &result)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	if gotBody["method"] != "user.get" {
		t.Errorf("method = %v", gotBody["method"])
	}
	if gotBody["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v", gotBody["jsonrpc"])
	}
	if _, ok := gotBody["params"].(map[string]any); !ok {
		t.Errorf("params = %v", gotBody["params"])
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if len(result) != 1 || result[0].Username != "alice" {
		t.Errorf("result = %+v", result)
	}
}

func TestCallRPCError(t *testing.T) {
	srv := newRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params."},"id":1}`))
	})
	c := NewRPCClient(srv.URL)
	var result any
	err := c.Call(context.Background(), "role.get", nil, &result)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "-32602") || !strings.Contains(err.Error(), "Invalid params") {
		t.Errorf("error = %v", err)
	}
}

func TestCallHTTPError(t *testing.T) {
	srv := newRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := NewRPCClient(srv.URL)
	var result any
	err := c.Call(context.Background(), "user.get", nil, &result)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected HTTP 500 error, got %v", err)
	}
}

func TestCallMalformedResponse(t *testing.T) {
	srv := newRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	})
	c := NewRPCClient(srv.URL)
	var result any
	err := c.Call(context.Background(), "user.get", nil, &result)
	if err == nil {
		t.Fatal("expected error on malformed response")
	}
}

func TestCallTransportError(t *testing.T) {
	c := NewRPCClient("http://127.0.0.1:1/api_jsonrpc.php", WithTimeout(200*time.Millisecond))
	var result any
	err := c.Call(context.Background(), "user.get", nil, &result)
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestCallTypeMismatch(t *testing.T) {
	srv := newRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","result":"unexpected shape","id":1}`))
	})
	c := NewRPCClient(srv.URL)
	var result []int
	err := c.Call(context.Background(), "user.get", nil, &result)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestCallCustomHeaders(t *testing.T) {
	srv := newRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "yes" {
			t.Errorf("missing custom header")
		}
		w.Write([]byte(`{"jsonrpc":"2.0","result":{},"id":1}`))
	})
	c := NewRPCClient(srv.URL, WithHeaders(map[string]string{"X-Custom": "yes"}))
	var result map[string]any
	if err := c.Call(context.Background(), "ping", nil, &result); err != nil {
		t.Fatalf("Call: %v", err)
	}
}

func TestCallContextCancel(t *testing.T) {
	srv := newRPCServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Write([]byte(`{}`))
	})
	c := NewRPCClient(srv.URL, WithTimeout(10*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var result any
	err := c.Call(ctx, "user.get", nil, &result)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
