package docmost

import "golang.org/x/crypto/bcrypt"

// cost совпадает с bcrypt saltRounds = 12 в Docmost
// (apps/server/src/common/helpers/utils.ts).
const cost = 12

// HashPassword хеширует пароль в формате, совместимом с Docmost ($2a$/$2b$).
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword проверяет пароль против хеша (используется в тестах).
func VerifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
