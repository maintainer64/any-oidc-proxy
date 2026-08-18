package docmost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newMockDocmost(t *testing.T) *httptest.Server {
	t.Helper()
	type loginBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type setupBody struct {
		Name          string `json:"name"`
		Email         string `json:"email"`
		Password      string `json:"password"`
		WorkspaceName string `json:"workspaceName"`
		Hostname      string `json:"hostname,omitempty"`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var b loginBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if b.Email != "ivan@example.com" || b.Password == "" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "authToken", Value: "session-abc", HttpOnly: true, Path: "/"})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"email":"ivan@example.com"}}`))
	})
	mux.HandleFunc("/api/auth/setup", func(w http.ResponseWriter, r *http.Request) {
		var b setupBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if b.Email != "ivan@example.com" || b.Password == "" || b.WorkspaceName == "" {
			http.Error(w, "invalid setup payload", http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "authToken", Value: "session-setup", HttpOnly: true, Path: "/"})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"workspace":{"name":"Docs"}}`))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

func TestLoginReturnsCookies(t *testing.T) {
	srv := newMockDocmost(t)
	defer srv.Close()

	d := &DocmostBackend{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}
	cookies, err := d.login(context.Background(), "ivan@example.com", "random-pwd")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if len(cookies) != 1 || !strings.Contains(cookies[0], "authToken=session-abc") {
		t.Fatalf("cookies = %v, want authToken=session-abc", cookies)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	srv := newMockDocmost(t)
	defer srv.Close()

	d := &DocmostBackend{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := d.login(context.Background(), "wrong@example.com", "pwd")
	if err == nil {
		t.Fatalf("login прошёл с неверными данными")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v, want упоминание статуса", err)
	}
}

func TestSetupReturnsCookies(t *testing.T) {
	srv := newMockDocmost(t)
	defer srv.Close()

	d := &DocmostBackend{
		baseURL:       srv.URL,
		httpClient:    srv.Client(),
		workspaceName: "Docs",
		hostname:      "docs.gubanov.site",
	}
	cookies, err := d.setup(context.Background(), "ivan@example.com", "Ivan Ivanov", "random-pwd")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(cookies) != 1 || !strings.Contains(cookies[0], "authToken=session-setup") {
		t.Fatalf("cookies = %v, want authToken=session-setup", cookies)
	}
}

func TestLoginNoCookiesIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := &DocmostBackend{baseURL: srv.URL, httpClient: srv.Client()}
	_, err := d.login(context.Background(), "ivan@example.com", "pwd")
	if err == nil {
		t.Fatalf("expected error when no session cookies returned")
	}
}
