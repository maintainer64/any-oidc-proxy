package backend

import (
	"net"
	"net/http"
	"strings"
)

func parseAndRewriteCookies(setCookieHeaders []string, targetDomain string) []*http.Cookie {
	var cookies []*http.Cookie

	for _, header := range setCookieHeaders {
		// Парсим стандартными средствами
		if cookie := parseCookieHeader(header); cookie != nil {
			// Перезаписываем нужные поля
			cookie.Domain = cleanDomain(targetDomain)
			// SameSiteDefaultMode == 1 в net/http, ноль означает "атрибут отсутствует"
			if cookie.SameSite == http.SameSite(0) {
				cookie.SameSite = http.SameSiteLaxMode
			}
			cookies = append(cookies, cookie)
		}
	}

	return cookies
}

func cleanDomain(domain string) string {
	// Убираем порт если есть
	if strings.Contains(domain, ":") {
		host, _, err := net.SplitHostPort(domain)
		if err == nil && host != "" {
			return host
		}
	}
	return domain
}

func parseCookieHeader(header string) *http.Cookie {
	parts := strings.Split(header, ";")
	if len(parts) == 0 {
		return nil
	}

	// Базовый парсинг name=value
	nameValue := strings.SplitN(parts[0], "=", 2)
	if len(nameValue) != 2 {
		return nil
	}

	cookie := &http.Cookie{
		Name:  strings.TrimSpace(nameValue[0]),
		Value: strings.TrimSpace(nameValue[1]),
	}

	// Парсим атрибуты
	for i := 1; i < len(parts); i++ {
		attr := strings.TrimSpace(parts[i])
		lowerAttr := strings.ToLower(attr)

		if strings.HasPrefix(lowerAttr, "domain=") {
			// Уже будем перезаписывать
		} else if strings.HasPrefix(lowerAttr, "path=") {
			cookie.Path = attr[strings.Index(attr, "=")+1:]
		} else if strings.HasPrefix(lowerAttr, "expires=") {
			// Парсим дату...
		} else if strings.HasPrefix(lowerAttr, "max-age=") {
			// Парсим max-age...
		} else if lowerAttr == "secure" {
			cookie.Secure = true
		} else if lowerAttr == "httponly" {
			cookie.HttpOnly = true
		} else if strings.HasPrefix(lowerAttr, "samesite=") {
			switch strings.ToLower(strings.TrimPrefix(lowerAttr, "samesite=")) {
			case "lax":
				cookie.SameSite = http.SameSiteLaxMode
			case "strict":
				cookie.SameSite = http.SameSiteStrictMode
			case "none":
				cookie.SameSite = http.SameSiteNoneMode
			}
		}
	}

	return cookie
}

func containsAttr(attrs []string, attr string) bool {
	attrLower := strings.ToLower(attr)
	for _, a := range attrs {
		if strings.ToLower(strings.TrimSpace(a)) == attrLower {
			return true
		}
	}
	return false
}

func hasSameSiteAttr(attrs []string) bool {
	for _, a := range attrs {
		a = strings.TrimSpace(a)
		if strings.HasPrefix(strings.ToLower(a), "samesite=") {
			return true
		}
	}
	return false
}
