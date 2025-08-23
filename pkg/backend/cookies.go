package backend

import (
	"net/http"
)

type SimpleCookieManager struct {
	secure     bool
	cookieName string
}

func NewSimpleCookieManager(secure bool, cookieName string) *SimpleCookieManager {
	return &SimpleCookieManager{
		secure:     secure,
		cookieName: cookieName,
	}
}

func (m *SimpleCookieManager) SetSessionCookies(w http.ResponseWriter, r *http.Request, cookies []string) {
	for _, cookie := range cookies {
		rewritten := rewriteSetCookieDomain(cookie, r.Host, m.secure)
		w.Header().Add("Set-Cookie", rewritten)
	}
}

func (m *SimpleCookieManager) ClearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.secure,
	})
}
