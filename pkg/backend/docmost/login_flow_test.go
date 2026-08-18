package docmost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"any-oidc-proxy/pkg/backend"

	"github.com/google/uuid"
)

// TestLoginFirstRunDoesSetup проверяет первый вход в пустую инсталляцию:
// воркспейса нет — идёт initial setup через /api/auth/setup, браузер получает
// session-setup. После этого (как в реальной жизни — воркспейс создан
// самим Docmost) второй вход идёт обычным путём upsert+login.
func TestLoginFirstRunDoesSetup(t *testing.T) {
	db := newTestDB(t)
	srv := newMockDocmost(t)
	defer srv.Close()

	d := &DocmostBackend{
		db:            db,
		baseURL:       srv.URL,
		httpClient:    srv.Client(),
		workspaceName: "Docs",
		hostname:      "docs.gubanov.site",
	}

	resp, err := d.Login(context.Background(), "ivan@example.com", backend.UserData{Email: "ivan@example.com", Name: "Ivan Ivanov"})
	if err != nil {
		t.Fatalf("Login (setup): %v", err)
	}
	if len(resp.Cookies) != 1 || !strings.Contains(resp.Cookies[0], "authToken=session-setup") {
		t.Fatalf("cookies = %v, want authToken=session-setup", resp.Cookies)
	}

	// симулируем: setup создал воркспейс в Docmost (и у нас в БД)
	ws := Workspace{ID: uuid.New().String(), Name: "Docs"}
	if err := db.Create(&ws).Error; err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	resp, err = d.Login(context.Background(), "ivan@example.com", backend.UserData{Email: "ivan@example.com", Name: "Ivan Ivanov"})
	if err != nil {
		t.Fatalf("Login (standard): %v", err)
	}
	if len(resp.Cookies) != 1 || !strings.Contains(resp.Cookies[0], "authToken=session-abc") {
		t.Fatalf("cookies = %v, want authToken=session-abc", resp.Cookies)
	}

	var count int64
	db.Model(&User{}).Where("email = ?", "ivan@example.com").Count(&count)
	if count != 1 {
		t.Fatalf("users count = %d, want 1", count)
	}
	var u User
	if err := db.Where("email = ?", "ivan@example.com").First(&u).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if u.Password == nil || !strings.HasPrefix(*u.Password, "$2a$12$") {
		t.Errorf("password = %v, want bcrypt $2a$12$", u.Password)
	}
}

// TestLoginSetupFailsThenStandard — гонка: воркспейс появляется между
// проверкой в БД и вызовом setup (setup возвращает 409). Backend должен
// переключиться на обычный путь после того, как воркспейс виден в БД.
func TestLoginSetupFailsThenStandard(t *testing.T) {
	db := newTestDB(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "authToken", Value: "session-abc", HttpOnly: true, Path: "/"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/auth/setup", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"Workspace already initialized"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := &DocmostBackend{
		db:            db,
		baseURL:       srv.URL,
		httpClient:    srv.Client(),
		workspaceName: "Docs",
	}

	// воркспейса нет ни в БД, ни в Docmost — setup падает, fallback тоже пуст
	if _, err := d.Login(context.Background(), "ivan@example.com", backend.UserData{Email: "ivan@example.com"}); err == nil {
		t.Fatalf("Login должна была вернуть ошибку (воркспейс так и не появился)")
	}

	// воркспейс появился (как если бы конкурент создал его между вызовами)
	ws := Workspace{ID: uuid.New().String(), Name: "Docs"}
	if err := db.Create(&ws).Error; err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	d.workspaceID = "" // сброс кэша
	resp, err := d.Login(context.Background(), "ivan@example.com", backend.UserData{Email: "ivan@example.com", Name: "Ivan Ivanov"})
	if err != nil {
		t.Fatalf("Login (после появления воркспейса): %v", err)
	}
	if len(resp.Cookies) != 1 || !strings.Contains(resp.Cookies[0], "authToken=session-abc") {
		t.Fatalf("cookies = %v, want authToken=session-abc", resp.Cookies)
	}
}
