package docmost

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("s3cr3t-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$12$") {
		t.Errorf("hash = %q, want bcrypt prefix $2a$12$ (cost 12, как в Docmost)", hash)
	}
	if !VerifyPassword("s3cr3t-password", hash) {
		t.Errorf("VerifyPassword не подтвердил правильный пароль")
	}
	if VerifyPassword("wrong", hash) {
		t.Errorf("VerifyPassword принял неверный пароль")
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Errorf("bcrypt-хеши совпали при разных солях")
	}
}
