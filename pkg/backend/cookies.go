package backend

import (
	"net/http"
)

type SimpleCookieManager struct {
	secure             bool
	cookieNames        []string
	sameSiteLaxDisable bool
}

func NewSimpleCookieManager(secure bool, cookieNames []string) *SimpleCookieManager {
	return &SimpleCookieManager{
		secure:      secure,
		cookieNames: cookieNames,
	}
}

func (m *SimpleCookieManager) SetSessionCookies(w http.ResponseWriter, r *http.Request, cookies []string) {
	newCookies := parseAndRewriteCookies(cookies, r.Host)
	for _, cookie := range newCookies {
		cookie.Secure = m.secure
		cookie.Domain = ""
		cookie.Path = "/"
		http.SetCookie(w, cookie)
	}
}

func (m *SimpleCookieManager) ClearSessionCookies(w http.ResponseWriter) {
	for _, cookieName := range m.cookieNames {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   m.secure,
		})
	}

}
