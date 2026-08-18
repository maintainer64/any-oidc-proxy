package metabase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"any-oidc-proxy/pkg/backend"
)

// mockMetabase реализует минимальный Metabase API для тестов.
type mockMetabase struct {
	t             *testing.T
	users         map[string]User // key: email
	sessions      int
	sessionHits   int
	requireAdmin  bool
	nextUserID    int
	created       []map[string]any
	updated       []map[string]any
	reactivated   []int
	adminEmail    string
	adminPassword string
}

func newMockMetabase(t *testing.T) *mockMetabase {
	m := &mockMetabase{
		t:             t,
		users:         map[string]User{},
		nextUserID:    1,
		adminEmail:    "admin@example.com",
		adminPassword: "adminpass",
	}
	return m
}

func (m *mockMetabase) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/session":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			m.sessionHits++
			if m.requireAdmin && (body["username"] != m.adminEmail || body["password"] != m.adminPassword) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"message":"wrong credentials"}`))
				return
			}
			m.sessions++
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":"adminsession123"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/user" && r.URL.Query().Get("status") == "all":
			m.checkSession(t2r(r), w)
			users := make([]User, 0, len(m.users))
			for _, u := range m.users {
				users = append(users, u)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"data": users})
		case r.Method == http.MethodPost && r.URL.Path == "/api/user":
			m.checkSession(t2r(r), w)
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			email := body["email"].(string)
			id := m.nextUserID
			m.nextUserID++
			u := User{
				ID:        id,
				Email:     email,
				FirstName: body["first_name"].(string),
				LastName:  body["last_name"].(string),
				IsActive:  true,
			}
			m.users[email] = u
			m.created = append(m.created, body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(u)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/user/") && strings.HasSuffix(r.URL.Path, "/password"):
			m.checkSession(t2r(r), w)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/user/") && strings.HasSuffix(r.URL.Path, "/reactivate"):
			m.checkSession(t2r(r), w)
			m.reactivated = append(m.reactivated, idFromPath(r.URL.Path))
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/user/"):
			m.checkSession(t2r(r), w)
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			m.updated = append(m.updated, body)
			w.WriteHeader(http.StatusOK)
		default:
			m.t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func t2r(r *http.Request) *http.Request { return r }

func (m *mockMetabase) checkSession(r *http.Request, w http.ResponseWriter) {
	if r.Header.Get("X-Metabase-Session") != "adminsession123" {
		m.t.Errorf("missing admin session header in %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func idFromPath(p string) int {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	var id int
	for _, s := range parts {
		if s != "" && strings.IndexByte(s, '.') < 0 && s != "user" && s != "reactivate" && s != "password" {
			id = strToInt(s)
		}
	}
	return id
}

func strToInt(s string) int {
	var n int
	for _, ch := range s {
		n = n*10 + int(ch-'0')
	}
	return n
}

func newClient(t *testing.T, m *mockMetabase) *ClientOIDC {
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &ClientOIDC{
		BaseURL:        u,
		AdminEmail:     "admin@example.com",
		AdminPassword:  "adminpass",
		HTTP:           srv.Client(),
		AdminSessionMu: &sync.Mutex{},
	}
}

func TestFindOrCreateUserCreates(t *testing.T) {
	m := newMockMetabase(t)
	c := newClient(t, m)

	u, err := c.FindOrCreateUser(context.Background(), "alice@gubanov.site", "Alice", "Smith", "pw123")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if u.ID == 0 || u.Email != "alice@gubanov.site" {
		t.Errorf("created user = %+v", u)
	}
	if len(m.created) != 1 {
		t.Errorf("expected 1 creation, got %d", len(m.created))
	}
	body := m.created[0]
	if body["first_name"] != "Alice" || body["last_name"] != "Smith" || body["password"] != "pw123" {
		t.Errorf("create body = %+v", body)
	}
}

func TestFindOrCreateUserFindsExisting(t *testing.T) {
	m := newMockMetabase(t)
	m.users["alice@gubanov.site"] = User{ID: 42, Email: "alice@gubanov.site", FirstName: "Alice", IsActive: true}
	c := newClient(t, m)

	u, err := c.FindOrCreateUser(context.Background(), "alice@gubanov.site", "Alice", "X", "pw")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if u.ID != 42 {
		t.Errorf("expected existing user id 42, got %d", u.ID)
	}
	if len(m.created) != 0 {
		t.Errorf("expected no creation, got %d", len(m.created))
	}
}

func TestFindUserByEmailCaseInsensitive(t *testing.T) {
	m := newMockMetabase(t)
	m.users["Alice@Gubanov.Site"] = User{ID: 7, Email: "Alice@Gubanov.Site", IsActive: true}
	c := newClient(t, m)

	u, err := c.FindUserByEmail(context.Background(), "alice@gubanov.site")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if u == nil || u.ID != 7 {
		t.Errorf("expected user 7, got %+v", u)
	}
}

func TestDoJSONRetriesOnExpiredSession(t *testing.T) {
	m := newMockMetabase(t)
	c := newClient(t, m)

	if err := c.ensureAdmin(context.Background()); err != nil {
		t.Fatalf("ensureAdmin: %v", err)
	}
	if c.AdminSession != "adminsession123" {
		t.Fatalf("admin session = %q", c.AdminSession)
	}

	// Принудительно протухшая сессия — doJSON должен перелогиниться
	c.AdminSession = "expired"
	c.AdminSessionExp = time.Now().Add(-time.Hour)

	resp, err := c.doJSON(context.Background(), http.MethodGet, &url.URL{Path: "/api/user", RawQuery: "status=all"}, nil)
	if err != nil {
		t.Fatalf("doJSON: %v", err)
	}
	resp.Body.Close()
	if m.sessionHits != 2 {
		t.Errorf("expected 2 session logins (initial + refresh), got %d", m.sessionHits)
	}
	if c.AdminSession != "adminsession123" {
		t.Errorf("session not restored, got %q", c.AdminSession)
	}
}

func TestEnsureAdminCachesValidSession(t *testing.T) {
	m := newMockMetabase(t)
	c := newClient(t, m)

	if err := c.ensureAdmin(context.Background()); err != nil {
		t.Fatalf("ensureAdmin: %v", err)
	}
	if err := c.ensureAdmin(context.Background()); err != nil {
		t.Fatalf("ensureAdmin (2nd): %v", err)
	}
	if m.sessionHits != 1 {
		t.Errorf("expected 1 session login, got %d", m.sessionHits)
	}
}

func TestEnsureAdminWrongPassword(t *testing.T) {
	m := newMockMetabase(t)
	m.requireAdmin = true
	c := newClient(t, m)
	c.AdminPassword = "wrong"

	if err := c.ensureAdmin(context.Background()); err == nil {
		t.Fatal("expected error on wrong admin password")
	}
}

func TestLoginUser(t *testing.T) {
	m := newMockMetabase(t)
	c := newClient(t, m)

	sessionID, setCookies, err := c.LoginUser(context.Background(), "alice@gubanov.site", "pw")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if sessionID != "adminsession123" {
		t.Errorf("session id = %q", sessionID)
	}
	if len(setCookies) != 0 {
		t.Errorf("unexpected set-cookies: %v", setCookies)
	}
}

func TestMetabaseBackendProvisionAndLogin(t *testing.T) {
	m := newMockMetabase(t)
	c := newClient(t, m)
	b := &MetabaseBackend{client: c}

	userID, err := b.ProvisionUser(context.Background(), backend.UserData{
		Email: "alice@gubanov.site", FirstName: "Alice", LastName: "Smith",
	})
	if err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}
	if userID != "1" {
		t.Errorf("user id = %q", userID)
	}
	if len(m.reactivated) != 1 {
		t.Errorf("expected 1 reactivate call, got %d", len(m.reactivated))
	}

	// Проверка, что пароль действительно сброшен и юзер залогинен
	redirect, err := b.Login(context.Background(), userID, backend.UserData{
		Email: "alice@gubanov.site", FirstName: "Alice", LastName: "Smith",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if redirect == nil {
		t.Fatal("expected redirect")
	}
}

func TestMetabaseBackendLoginInvalidUserID(t *testing.T) {
	m := newMockMetabase(t)
	c := newClient(t, m)
	b := &MetabaseBackend{client: c}

	_, err := b.Login(context.Background(), "not-a-number", backend.UserData{Email: "x@y.z"})
	if err == nil {
		t.Fatal("expected error for invalid user id")
	}
}
