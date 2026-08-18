package plane

import (
	"strings"
	"testing"
)

func TestGenerateAndVerifyRoundtrip(t *testing.T) {
	hash, err := Generate("s3cret-pass")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 4 {
		t.Fatalf("unexpected hash format %q", hash)
	}
	if parts[0] != Algorithm {
		t.Errorf("algorithm = %q", parts[0])
	}
	if parts[1] != "600000" {
		t.Errorf("iterations = %q", parts[1])
	}
	if len(parts[2]) != SaltLength {
		t.Errorf("salt length = %d", len(parts[2]))
	}

	ok, err := Verify("s3cret-pass", hash)
	if err != nil || !ok {
		t.Errorf("Verify correct password: ok=%v err=%v", ok, err)
	}
	ok, err = Verify("wrong", hash)
	if err != nil || ok {
		t.Errorf("Verify wrong password: ok=%v err=%v", ok, err)
	}
}

// Вектор, посчитанный независимо (Python hashlib.pbkdf2_hmac, 600000 итераций).
// Формат: pbkdf2_sha256$<iter>$<salt>$<b64>, как в Django.
func TestVerifyAgainstKnownVector(t *testing.T) {
	const hash = "pbkdf2_sha256$600000$abcdefghijkl$em3J66v0e8Dq/5HSO+bfOv0RhRH2h4W3AMv3uEz0mws="
	ok, err := Verify("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Errorf("vector verify: ok=%v err=%v", ok, err)
	}
	ok, err = Verify("wrong password", hash)
	if err != nil || ok {
		t.Errorf("vector negative: ok=%v err=%v", ok, err)
	}
}

func TestEncodeDeterministic(t *testing.T) {
	a := Encode("pw", "saltsalt123", 600000)
	b := Encode("pw", "saltsalt123", 600000)
	if a != b {
		t.Errorf("Encode not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "pbkdf2_sha256$600000$saltsalt123$") {
		t.Errorf("unexpected encoded %q", a)
	}
}

func TestVerifyErrors(t *testing.T) {
	cases := []struct {
		name string
		hash string
	}{
		{"wrong parts count", "pbkdf2_sha256$600000$salt"},
		{"empty", ""},
		{"wrong algorithm", "md5$600000$salt$hash"},
		{"bad iterations", "pbkdf2_sha256$abc$salt$hash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify("pw", tc.hash); err == nil {
				t.Errorf("expected error for %q", tc.hash)
			}
		})
	}
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt(SaltLength)
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt) != SaltLength {
		t.Errorf("salt len = %d", len(salt))
	}
	for _, ch := range salt {
		if !strings.ContainsRune(saltAlphabet, ch) {
			t.Errorf("illegal salt char %q", ch)
		}
	}
	if _, err := GenerateSalt(0); err == nil {
		t.Error("expected error for 0 length")
	}
	if _, err := GenerateSalt(-1); err == nil {
		t.Error("expected error for negative length")
	}
}

func TestGenerateSaltUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		salt, _ := GenerateSalt(SaltLength)
		if seen[salt] {
			t.Fatal("duplicate salt generated")
		}
		seen[salt] = true
	}
}
