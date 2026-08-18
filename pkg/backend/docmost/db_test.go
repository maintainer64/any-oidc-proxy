package docmost

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const usersTable = `
CREATE TABLE IF NOT EXISTS users (
	id                    uuid PRIMARY KEY,
	name                  text,
	email                 text NOT NULL,
	email_verified_at     timestamptz,
	password              text,
	avatar_url            text,
	role                  text,
	invited_by_id         uuid,
	workspace_id          uuid,
	locale                text,
	timezone              text,
	last_active_at        timestamptz,
	last_login_at         timestamptz,
	deactivated_at        timestamptz,
	deleted_at            timestamptz,
	has_generated_password boolean,
	scim_external_id      text,
	created_at            timestamptz NOT NULL DEFAULT now(),
	updated_at            timestamptz NOT NULL DEFAULT now()
);`

const workspacesTable = `
CREATE TABLE IF NOT EXISTS workspaces (
	id         uuid PRIMARY KEY,
	name       text,
	hostname   text,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	deleted_at timestamptz
);`

// newTestDB открывает БД из TEST_DATABASE_URL и приводит её к чистому состоянию.
// Без переменной окружения тесты пропускаются.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database tests")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Exec(`DROP TABLE IF EXISTS users, workspaces`).Error; err != nil {
		t.Fatalf("drop tables: %v", err)
	}
	if err := db.Exec(usersTable).Error; err != nil {
		t.Fatalf("create users table: %v", err)
	}
	if err := db.Exec(workspacesTable).Error; err != nil {
		t.Fatalf("create workspaces table: %v", err)
	}
	if err := db.Exec(`TRUNCATE users, workspaces`).Error; err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return db
}

func TestGetWorkspaceID(t *testing.T) {
	db := newTestDB(t)
	d := &DocmostBackend{db: db, workspaceName: "Docs"}

	if _, err := d.getWorkspaceID(); err != errNoWorkspace {
		t.Fatalf("без воркспейса: err = %v, want errNoWorkspace", err)
	}

	ws := Workspace{ID: uuid.New().String(), Name: "Docs"}
	if err := db.Create(&ws).Error; err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	id, err := d.getWorkspaceID()
	if err != nil {
		t.Fatalf("getWorkspaceID: %v", err)
	}
	if id != ws.ID {
		t.Fatalf("id = %q, want %q", id, ws.ID)
	}

	// кэш: второй вызов не должен падать
	if _, err := d.getWorkspaceID(); err != nil {
		t.Fatalf("cached getWorkspaceID: %v", err)
	}
}

func TestUpsertUser(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	ws := Workspace{ID: uuid.New().String(), Name: "Docs"}
	if err := db.Create(&ws).Error; err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	d := &DocmostBackend{db: db}

	err := d.upsertUser(ctx, "ivan@example.com", "Ivan Ivanov", "random-password-1", ws.ID)
	if err != nil {
		t.Fatalf("upsertUser (create): %v", err)
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
	if u.Password == nil || !VerifyPassword("random-password-1", *u.Password) {
		t.Errorf("password hash не проверяется")
	}
	if *u.Role != "member" {
		t.Errorf("role = %q, want member", *u.Role)
	}
	if u.HasGeneratedPassword == nil || !*u.HasGeneratedPassword {
		t.Errorf("has_generated_password = %v, want true", u.HasGeneratedPassword)
	}

	// второй заход — должен обновить пароль, а не создать дубликат
	err = d.upsertUser(ctx, "ivan@example.com", "Ivan Ivanov", "random-password-2", ws.ID)
	if err != nil {
		t.Fatalf("upsertUser (update): %v", err)
	}
	db.Model(&User{}).Where("email = ?", "ivan@example.com").Count(&count)
	if count != 1 {
		t.Fatalf("users count = %d, want 1 (no duplicates)", count)
	}
	if err := db.Where("email = ?", "ivan@example.com").First(&u).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if !VerifyPassword("random-password-2", *u.Password) {
		t.Errorf("пароль не обновился")
	}

	// тот же email в другом воркспейсе — отдельный пользователь
	ws2 := Workspace{ID: uuid.New().String(), Name: "Docs2"}
	if err := db.Create(&ws2).Error; err != nil {
		t.Fatalf("create workspace 2: %v", err)
	}
	if err := d.upsertUser(ctx, "ivan@example.com", "Ivan", "random-password-3", ws2.ID); err != nil {
		t.Fatalf("upsertUser (workspace 2): %v", err)
	}
	db.Model(&User{}).Where("email = ?", "ivan@example.com").Count(&count)
	if count != 2 {
		t.Fatalf("users count = %d, want 2", count)
	}
}
