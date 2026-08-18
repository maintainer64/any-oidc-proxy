package plane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockPlaneAuth struct {
	t          *testing.T
	csrfToken  string
	signInBody map[string]string
	cookies    []string
	csrfStatus int
	signStatus int
}

func newMockPlaneAuth(t *testing.T) *mockPlaneAuth {
	return &mockPlaneAuth{
		csrfToken:  "csrf-xyz",
		cookies:    []string{"sessionid=sess123; Path=/; HttpOnly"},
		csrfStatus: http.StatusOK,
		signStatus: http.StatusFound,
	}
}

func (m *mockPlaneAuth) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/auth/get-csrf-token/":
			if m.csrfStatus != http.StatusOK {
				w.WriteHeader(m.csrfStatus)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: m.csrfToken, Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"csrf_token":"` + m.csrfToken + `"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/auth/sign-in/":
			if err := r.ParseForm(); err != nil {
				m.t.Fatalf("parse form: %v", err)
			}
			m.signInBody = map[string]string{
				"csrfmiddlewaretoken": r.FormValue("csrfmiddlewaretoken"),
				"email":               r.FormValue("email"),
				"password":            r.FormValue("password"),
			}
			if m.signStatus != http.StatusOK && m.signStatus != http.StatusFound && m.signStatus != http.StatusSeeOther {
				w.WriteHeader(m.signStatus)
				return
			}
			for _, c := range m.cookies {
				w.Header().Add("Set-Cookie", c)
			}
			w.WriteHeader(m.signStatus)
		default:
			m.t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func newPlaneBackendForAuth(t *testing.T, m *mockPlaneAuth) (*PlaneBackend, *httptest.Server) {
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	return &PlaneBackend{
		baseURL:    srv.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}, srv
}

func TestLoginUserSuccess(t *testing.T) {
	m := newMockPlaneAuth(t)
	pb, _ := newPlaneBackendForAuth(t, m)

	cookies, err := pb.loginUser(context.Background(), "alice@gubanov.site", "pw")
	if err != nil {
		t.Fatalf("loginUser: %v", err)
	}
	if len(cookies) != 1 || cookies[0] != "sessionid=sess123; Path=/; HttpOnly" {
		t.Errorf("cookies = %v", cookies)
	}
	if m.signInBody == nil {
		t.Fatal("sign-in not called")
	}
	if m.signInBody["csrfmiddlewaretoken"] != "csrf-xyz" {
		t.Errorf("csrf token in form = %q", m.signInBody["csrfmiddlewaretoken"])
	}
	if m.signInBody["email"] != "alice@gubanov.site" || m.signInBody["password"] != "pw" {
		t.Errorf("sign-in form = %v", m.signInBody)
	}
}

func TestLoginUserCSRFFailure(t *testing.T) {
	m := newMockPlaneAuth(t)
	m.csrfStatus = http.StatusInternalServerError
	pb, _ := newPlaneBackendForAuth(t, m)

	if _, err := pb.loginUser(context.Background(), "a@b.c", "pw"); err == nil {
		t.Fatal("expected error on csrf failure")
	}
}

func TestLoginUserEmptyCSRFToken(t *testing.T) {
	m := newMockPlaneAuth(t)
	m.csrfToken = ""
	pb, _ := newPlaneBackendForAuth(t, m)

	if _, err := pb.loginUser(context.Background(), "a@b.c", "pw"); err == nil {
		t.Fatal("expected error on empty csrf token")
	}
}

func TestLoginUserSignInFailure(t *testing.T) {
	m := newMockPlaneAuth(t)
	m.signStatus = http.StatusForbidden
	pb, _ := newPlaneBackendForAuth(t, m)

	if _, err := pb.loginUser(context.Background(), "a@b.c", "pw"); err == nil {
		t.Fatal("expected error on sign-in failure")
	}
}

func TestLoginUserSendsCSRFCookie(t *testing.T) {
	m := newMockPlaneAuth(t)
	m.csrfToken = "token-from-cookie"
	pb, _ := newPlaneBackendForAuth(t, m)

	// CookieJar должен подхватить csrftoken из Set-Cookie на GET-шаге
	_ = pb
	if _, err := pb.loginUser(context.Background(), "a@b.c", "pw"); err != nil {
		t.Fatalf("loginUser: %v", err)
	}
	if m.signInBody == nil || m.signInBody["csrfmiddlewaretoken"] != "token-from-cookie" {
		t.Errorf("expected csrf token from cookie jar in form, got %v", m.signInBody)
	}
}
