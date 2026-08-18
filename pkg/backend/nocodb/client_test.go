package nocodb

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

type mockNocodb struct {
	t             *testing.T
	users         map[string]User
	userIDs       map[string]bool
	signinHits    int
	requireAdmin  bool
	adminEmail    string
	adminPassword string
	nextID        int
	created       []map[string]any
	resetURLs     []string
	passwordSets  []string
}

func newMockNocodb(t *testing.T) *mockNocodb {
	return &mockNocodb{
		t:             t,
		users:         map[string]User{},
		userIDs:       map[string]bool{},
		adminEmail:    "admin@example.com",
		adminPassword: "adminpass",
		nextID:        1,
	}
}

func (m *mockNocodb) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/user/signin":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			m.signinHits++
			if m.requireAdmin && body["email"] == m.adminEmail && body["password"] != m.adminPassword {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"msg":"wrong credentials"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"token":"token-` + body["email"] + `"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/users":
			if !m.checkAuth(r, w) {
				return
			}
			list := make([]User, 0, len(m.users))
			for _, u := range m.users {
				list = append(list, u)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"list":     list,
				"pageInfo": map[string]any{"totalRows": len(list)},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/users":
			if !m.checkAuth(r, w) {
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			id := "uuid-" + string(rune('0'+m.nextID))
			m.nextID++
			u := User{
				ID:          id,
				Email:       body["email"].(string),
				DisplayName: body["firstname"].(string) + " " + body["lastname"].(string),
			}
			m.users[u.Email] = u
			m.userIDs[id] = true
			m.created = append(m.created, body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(u)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/generate-reset-url"):
			if !m.checkAuth(r, w) {
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/users/"), "/generate-reset-url")
			if !m.userIDs[id] {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"msg":"user not found"}`))
				return
			}
			m.resetURLs = append(m.resetURLs, id)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"reset_password_token":"reset-token-` + id + `"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/auth/password/reset/"):
			if !m.checkAuth(r, w) {
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			m.passwordSets = append(m.passwordSets, body["password"].(string))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		default:
			m.t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (m *mockNocodb) checkAuth(r *http.Request, w http.ResponseWriter) bool {
	token := r.Header.Get("xc-auth")
	if token == "expired" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"msg":"token expired"}`))
		return false
	}
	if token != "token-admin@example.com" {
		m.t.Errorf("missing admin token in %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func newNocodbClient(t *testing.T, m *mockNocodb) *ClientOIDC {
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &ClientOIDC{
		BaseURL:       u,
		AdminEmail:    m.adminEmail,
		AdminPassword: m.adminPassword,
		HTTP:          srv.Client(),
		AdminTokenMu:  &sync.Mutex{},
	}
}

func TestNocodbFindOrCreateUserCreates(t *testing.T) {
	m := newMockNocodb(t)
	c := newNocodbClient(t, m)

	u, err := c.FindOrCreateUser(context.Background(), "alice@gubanov.site", "Alice", "Smith", "pw123")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if u.ID == "" || u.Email != "alice@gubanov.site" {
		t.Errorf("created user = %+v", u)
	}
	if len(m.created) != 1 {
		t.Fatalf("expected 1 creation, got %d", len(m.created))
	}
	body := m.created[0]
	if body["roles"] != "org-level-creator" {
		t.Errorf("roles = %v", body["roles"])
	}
	if body["password"] != "pw123" {
		t.Errorf("password not passed to create: %v", body["password"])
	}
}

func TestNocodbFindOrCreateUserFindsExisting(t *testing.T) {
	m := newMockNocodb(t)
	m.users["alice@gubanov.site"] = User{ID: "uuid-9", Email: "alice@gubanov.site"}
	c := newNocodbClient(t, m)

	u, err := c.FindOrCreateUser(context.Background(), "alice@gubanov.site", "Alice", "X", "pw")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if u.ID != "uuid-9" {
		t.Errorf("expected existing user, got %+v", u)
	}
	if len(m.created) != 0 {
		t.Errorf("expected no creation, got %d", len(m.created))
	}
}

func TestNocodbResetPasswordFlow(t *testing.T) {
	m := newMockNocodb(t)
	m.users["alice@gubanov.site"] = User{ID: "uuid-1", Email: "alice@gubanov.site"}
	m.userIDs["uuid-1"] = true
	c := newNocodbClient(t, m)

	token, err := c.PasswordGenerateResetUrl(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("PasswordGenerateResetUrl: %v", err)
	}
	if token.ResetPasswordToken != "reset-token-uuid-1" {
		t.Errorf("token = %+v", token)
	}
	if err := c.PasswordSet(context.Background(), token, "newpass"); err != nil {
		t.Fatalf("PasswordSet: %v", err)
	}
	if len(m.passwordSets) != 1 || m.passwordSets[0] != "newpass" {
		t.Errorf("password sets = %v", m.passwordSets)
	}
}

func TestNocodbLoginUser(t *testing.T) {
	m := newMockNocodb(t)
	c := newNocodbClient(t, m)

	token, setCookies, err := c.LoginUser(context.Background(), "alice@gubanov.site", "pw")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if token != "token-alice@gubanov.site" {
		t.Errorf("token = %q", token)
	}
	if len(setCookies) != 0 {
		t.Errorf("unexpected cookies %v", setCookies)
	}
}

func TestNocodbDoJSONRetriesOnExpiredToken(t *testing.T) {
	m := newMockNocodb(t)
	c := newNocodbClient(t, m)

	if err := c.ensureAdmin(context.Background()); err != nil {
		t.Fatalf("ensureAdmin: %v", err)
	}
	// Сервер уже считает токен протухшим, но клиент ещё нет — 401 заставит перелогиниться
	c.AdminToken = "expired"
	c.AdminTokenExp = time.Now().Add(time.Hour)

	_, err := c.ListUsersByEmail(context.Background(), "alice@gubanov.site")
	if err != nil {
		t.Fatalf("ListUsersByEmail: %v", err)
	}
	if c.AdminToken != "token-admin@example.com" {
		t.Errorf("token not refreshed, got %q", c.AdminToken)
	}
}

func TestNocodbEnsureAdminCaches(t *testing.T) {
	m := newMockNocodb(t)
	c := newNocodbClient(t, m)

	if err := c.ensureAdmin(context.Background()); err != nil {
		t.Fatalf("ensureAdmin: %v", err)
	}
	if err := c.ensureAdmin(context.Background()); err != nil {
		t.Fatalf("ensureAdmin 2nd: %v", err)
	}
	if m.signinHits != 1 {
		t.Errorf("expected 1 signin, got %d", m.signinHits)
	}
}

func TestNocodbBackendProvisionAndLogin(t *testing.T) {
	m := newMockNocodb(t)
	c := newNocodbClient(t, m)
	b := &NocodbBackend{client: c}

	userID, err := b.ProvisionUser(context.Background(), backend.UserData{
		Email: "alice@gubanov.site", FirstName: "Alice", LastName: "Smith",
	})
	if err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}
	if userID == "" {
		t.Error("empty user id")
	}

	redirect, err := b.Login(context.Background(), userID, backend.UserData{
		Email: "alice@gubanov.site", FirstName: "Alice", LastName: "Smith",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if redirect == nil {
		t.Fatal("expected redirect")
	}
	if len(m.resetURLs) != 1 {
		t.Errorf("expected 1 reset-url call, got %d", len(m.resetURLs))
	}
	if len(m.passwordSets) != 1 {
		t.Errorf("expected 1 password set, got %d", len(m.passwordSets))
	}
}

func TestNocodbBackendLoginMissingUser(t *testing.T) {
	m := newMockNocodb(t)
	c := newNocodbClient(t, m)
	b := &NocodbBackend{client: c}

	// Reset URL для несуществующего пользователя → мок вернёт 404 → ошибка
	_, err := b.Login(context.Background(), "uuid-missing", backend.UserData{Email: "x@y.z"})
	if err == nil {
		t.Fatal("expected error")
	}
}
