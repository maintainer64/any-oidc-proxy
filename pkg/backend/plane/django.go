package plane

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	Algorithm    = "pbkdf2_sha256"
	Iterations   = 600_000
	DKLen        = 32 // Django для sha256 использует длину ключа равную размеру дайджеста (32 байта)
	SaltLength   = 12 // типичная длина соли в Django по умолчанию
	saltAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// GenerateSalt генерирует случайную соль из разрешённых Django символов.
func GenerateSalt(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("salt length must be > 0")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	alphabet := []byte(saltAlphabet)
	out := make([]byte, n)
	for i := range buf {
		out[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(out), nil
}

// Encode формирует строку в формате Django: pbkdf2_sha256$<iterations>$<salt>$<base64>
func Encode(password, salt string, iterations int) string {
	dk := pbkdf2.Key([]byte(password), []byte(salt), iterations, DKLen, sha256.New)
	hashB64 := base64.StdEncoding.EncodeToString(dk) // с '='-паддингом, как в Django
	return fmt.Sprintf("%s$%d$%s$%s", Algorithm, iterations, salt, hashB64)
}

// Generate хеширует пароль с новой случайной солью и возвращает строку Django.
func Generate(password string) (string, error) {
	salt, err := GenerateSalt(SaltLength)
	if err != nil {
		return "", err
	}
	return Encode(password, salt, Iterations), nil
}

// Verify проверяет пароль против строки Django-подобного хеша.
func Verify(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 {
		return false, errors.New("invalid encoded format")
	}
	if parts[0] != Algorithm {
		return false, errors.New("unsupported algorithm")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, err
	}
	salt := parts[2]
	candidate := Encode(password, salt, iter)
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(encoded)) == 1, nil
}
