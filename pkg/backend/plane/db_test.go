package plane

import (
	"context"
	"os"
	"testing"

	"any-oidc-proxy/pkg/backend"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping DB test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.Exec("DROP TABLE IF EXISTS users").Error; err != nil {
		t.Fatalf("drop users: %v", err)
	}
	if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`).Error; err != nil {
		t.Fatalf("create extension: %v", err)
	}
	if err := db.AutoMigrate(&User{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func TestCreateOrUpdateUserCreate(t *testing.T) {
	db := testDB(t)
	pb := &PlaneBackend{db: db}

	u, err := pb.createOrUpdateUser("alice@gubanov.site", "Alice", "Smith", "s3cret-pass")
	if err != nil {
		t.Fatalf("createOrUpdateUser: %v", err)
	}
	if u.ID == "" {
		t.Error("expected generated id")
	}
	if u.Email != "alice@gubanov.site" {
		t.Errorf("email = %q", u.Email)
	}

	var count int64
	db.Model(&User{}).Where("email = ?", "alice@gubanov.site").Count(&count)
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}

	var stored User
	db.Where("email = ?", "alice@gubanov.site").First(&stored)
	ok, err := Verify("s3cret-pass", stored.Password)
	if err != nil || !ok {
		t.Errorf("stored hash does not verify: ok=%v err=%v", ok, err)
	}
	if stored.DisplayName != "Alice Smith" {
		t.Errorf("display_name = %q", stored.DisplayName)
	}
	if !stored.IsEmailVerified || !stored.IsActive {
		t.Errorf("expected active+verified user, got %+v", stored)
	}
}

func TestCreateOrUpdateUserUpdate(t *testing.T) {
	db := testDB(t)
	pb := &PlaneBackend{db: db}

	if _, err := pb.createOrUpdateUser("bob@gubanov.site", "Bob", "Doe", "old-pass"); err != nil {
		t.Fatalf("create: %v", err)
	}
	u2, err := pb.createOrUpdateUser("bob@gubanov.site", "Robert", "Doe", "new-pass")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if u2.ID == "" {
		t.Error("expected existing id kept")
	}

	var count int64
	db.Model(&User{}).Where("email = ?", "bob@gubanov.site").Count(&count)
	if count != 1 {
		t.Errorf("expected 1 row after update, got %d", count)
	}

	var stored User
	db.Where("email = ?", "bob@gubanov.site").First(&stored)
	ok, err := Verify("new-pass", stored.Password)
	if err != nil || !ok {
		t.Errorf("new hash does not verify: ok=%v err=%v", ok, err)
	}
	ok, _ = Verify("old-pass", stored.Password)
	if ok {
		t.Error("old password should not verify")
	}
	if stored.FirstName != "Robert" {
		t.Errorf("first_name not updated: %q", stored.FirstName)
	}
}

func TestBackendLoginFlowWithDB(t *testing.T) {
	db := testDB(t)
	m := newMockPlaneAuth(t)
	pb, _ := newPlaneBackendForAuth(t, m)
	pb.db = db

	redirect, err := pb.Login(context.Background(), "alice@gubanov.site", backend.UserData{
		Email:     "alice@gubanov.site",
		FirstName: "Alice",
		LastName:  "Smith",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if redirect == nil || len(redirect.Cookies) == 0 {
		t.Fatalf("expected cookies in redirect, got %+v", redirect)
	}

	var stored User
	db.Where("email = ?", "alice@gubanov.site").First(&stored)
	if stored.ID == "" {
		t.Fatal("user not persisted")
	}
}
