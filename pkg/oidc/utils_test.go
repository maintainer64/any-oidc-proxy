package oidcauth

import (
	"strings"
	"testing"
)

const pwAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_@#"

func TestGenPassword(t *testing.T) {
	for _, n := range []int{1, 8, 24, 64} {
		pw := GenPassword(n)
		if len(pw) != n {
			t.Errorf("GenPassword(%d) returned %d chars", n, len(pw))
		}
		for _, ch := range pw {
			if !strings.ContainsRune(pwAlphabet, ch) {
				t.Errorf("unexpected character %q in generated password", ch)
			}
		}
	}
}

func TestGenPasswordUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		pw := GenPassword(24)
		if seen[pw] {
			t.Fatal("generated duplicate password")
		}
		seen[pw] = true
	}
}
