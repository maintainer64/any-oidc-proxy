package oidcauth

import (
	cryptoRand "crypto/rand"
	"math/rand"
)

func GenPassword(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_@#"
	b := make([]byte, n)
	if _, err := cryptoRand.Read(b); err == nil {
		for i := 0; i < n; i++ {
			b[i] = letters[int(b[i])%len(letters)]
		}
		return string(b)
	}
	for i := 0; i < n; i++ {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
