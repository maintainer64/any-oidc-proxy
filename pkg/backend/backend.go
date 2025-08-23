package backend

import (
	"context"
	"net/http"
)

// UserData содержит информацию о пользователе
type UserData struct {
	Email     string
	FirstName string
	LastName  string
	Subject   string // OIDC sub
}

// Backend интерфейс для взаимодействия с целевой системой
type Backend interface {
	// ProvisionUser создает или обновляет пользователя в системе
	ProvisionUser(ctx context.Context, user UserData) (string, error)

	// Login выполняет вход пользователя и возвращает сессионные куки
	Login(ctx context.Context, userID string, userData UserData) ([]string, error)
}

// CookieManager управляет куками сессии
type CookieManager interface {
	SetSessionCookies(w http.ResponseWriter, r *http.Request, cookies []string)
	ClearSessionCookies(w http.ResponseWriter)
}
