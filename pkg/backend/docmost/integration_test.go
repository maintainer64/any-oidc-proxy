package docmost

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"any-oidc-proxy/pkg/backend"
)

// Интеграционный тест против РЕАЛЬНОГО docmost (контейнер) с уже
// завершённым initial setup — точная копия прод-состояния.
// Запуск:
//
//	DOCMOST_INTEGRATION_BASE_URL=http://localhost:8888 \
//	TEST_DATABASE_URL=postgresql://docmost:secret@localhost:5433/docmost \
//	go test ./pkg/backend/docmost/ -run TestIntegrationExistingWorkspace -v
func TestIntegrationExistingWorkspace(t *testing.T) {
	baseURL := os.Getenv("DOCMOST_INTEGRATION_BASE_URL")
	dsn := os.Getenv("TEST_DATABASE_URL")
	if baseURL == "" || dsn == "" {
		t.Skip("integration env not set")
	}
	// БД прокинута из контейнера e2e-pg на 5433
	pb, err := NewDocmostBackend(baseURL, dsn, &http.Client{Timeout: 15 * time.Second}, WithSetupParams("Docs", ""))
	if err != nil {
		t.Fatalf("NewDocmostBackend: %v", err)
	}

	// Воркспейс уже существует (мастер кто-то прошёл) — резолв должен пройти
	wsID, err := pb.getWorkspaceID()
	if err != nil {
		t.Fatalf("getWorkspaceID: %v", err)
	}
	t.Logf("workspaceID: %s", wsID)

	// Новый OIDC-пользователь: upsert + login — путь из проду
	redirect, err := pb.Login(context.Background(), "oidc.user@gubanov.site", backend.UserData{
		Email:     "oidc.user@gubanov.site",
		Name:      "OIDC User",
		FirstName: "OIDC",
		LastName:  "User",
	})
	if err != nil {
		t.Fatalf("Login(new user): %v", err)
	}
	if len(redirect.Cookies) == 0 {
		t.Fatal("no cookies returned")
	}
	t.Logf("login cookies: %v", redirect.Cookies)
}
