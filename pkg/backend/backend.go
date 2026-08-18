package backend

import (
	"context"
	"net/http"
)

// HTTPClient — минимальный интерфейс HTTP-клиента (тестируется моками).
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// UserData содержит информацию о пользователе
type UserData struct {
	Email     string
	Name      string
	FirstName string
	LastName  string
	Subject   string   // OIDC sub
	Groups    []string // OIDC sub
}

// UserRedirect содержит инфорацию для подстановки данных пользователю
type UserRedirect struct {
	Cookies          []string
	RedirectLocation string
}

// Backend интерфейс для взаимодействия с целевой системой
type Backend interface {
	// ProvisionUser создает или обновляет пользователя в системе
	ProvisionUser(ctx context.Context, user UserData) (string, error)

	// Login выполняет вход пользователя и возвращает сессионные куки
	Login(ctx context.Context, userID string, userData UserData) (*UserRedirect, error)
}

// CookieManager управляет куками сессии
type CookieManager interface {
	SetSessionCookies(w http.ResponseWriter, r *http.Request, cookies []string)
	ClearSessionCookies(w http.ResponseWriter)
}
