package backend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAndRewriteCookies(t *testing.T) {
	headers := []string{
		"session=abc123; Path=/; HttpOnly",
		"csrf=x; Domain=internal.local; SameSite=None; Secure",
	}
	cookies := parseAndRewriteCookies(headers, "docs.gubanov.site:8443")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	if cookies[0].Name != "session" || cookies[0].Value != "abc123" {
		t.Errorf("cookie[0] = %+v", cookies[0])
	}
	if !cookies[0].HttpOnly {
		t.Error("expected HttpOnly on cookie[0]")
	}

	if cookies[1].Domain != "docs.gubanov.site" {
		t.Errorf("expected domain rewritten to docs.gubanov.site, got %q", cookies[1].Domain)
	}
	if cookies[1].SameSite != http.SameSiteNoneMode {
		t.Errorf("expected SameSite=None preserved, got %v", cookies[1].SameSite)
	}
	if !cookies[1].Secure {
		t.Error("expected Secure preserved")
	}
}

func TestParseAndRewriteCookiesDefaultSameSite(t *testing.T) {
	cookies := parseAndRewriteCookies([]string{"a=1; Path=/"}, "host.example.com")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("expected default SameSite rewritten to Lax, got %v", cookies[0].SameSite)
	}
	if cookies[0].Domain != "host.example.com" {
		t.Errorf("expected domain set to host, got %q", cookies[0].Domain)
	}
}

func TestParseAndRewriteCookiesInvalid(t *testing.T) {
	for _, h := range []string{"", "noequals"} {
		cookies := parseAndRewriteCookies([]string{h}, "host.example.com")
		if len(cookies) != 0 {
			t.Errorf("header %q: expected no cookies, got %d", h, len(cookies))
		}
	}
}

func TestParseCookieHeaderAttributes(t *testing.T) {
	c := parseCookieHeader("tok=zz; Max-Age=3600; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Path=/sub; Secure; HttpOnly; SameSite=Strict")
	if c == nil {
		t.Fatal("expected cookie")
	}
	if c.Path != "/sub" {
		t.Errorf("path = %q", c.Path)
	}
	if !c.Secure || !c.HttpOnly {
		t.Errorf("expected secure+httponly, got %+v", c)
	}
}

func TestCleanDomain(t *testing.T) {
	cases := map[string]string{
		"docs.gubanov.site":     "docs.gubanov.site",
		"docs.gubanov.site:443": "docs.gubanov.site",
		"[::1]:8080":            "::1",
		"":                      "",
	}
	for in, want := range cases {
		if got := cleanDomain(in); got != want {
			t.Errorf("cleanDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSimpleCookieManagerSetSessionCookies(t *testing.T) {
	m := NewSimpleCookieManager(true, []string{"session", "csrf"})
	req := httptest.NewRequest(http.MethodGet, "http://docs.gubanov.site/", nil)
	rec := httptest.NewRecorder()

	m.SetSessionCookies(rec, req, []string{
		"session=abc; Path=/; HttpOnly",
		"csrf=xyz; Domain=old.internal; Path=/",
	})

	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie, got %d", len(cookies))
	}
	for _, c := range cookies {
		if c.Domain != "docs.gubanov.site" {
			t.Errorf("cookie %s: domain = %q", c.Name, c.Domain)
		}
		if c.Path != "/" {
			t.Errorf("cookie %s: path = %q", c.Name, c.Path)
		}
		if !c.Secure {
			t.Errorf("cookie %s: not secure", c.Name)
		}
	}
}

func TestSimpleCookieManagerClearSessionCookies(t *testing.T) {
	m := NewSimpleCookieManager(true, []string{"session", "csrf"})
	rec := httptest.NewRecorder()
	m.ClearSessionCookies(rec)

	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	for _, c := range cookies {
		if c.Name != "session" && c.Name != "csrf" {
			t.Errorf("unexpected cookie name %q", c.Name)
		}
		if c.MaxAge != -1 {
			t.Errorf("cookie %s: MaxAge = %d, want -1", c.Name, c.MaxAge)
		}
	}
	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) != 2 {
		t.Errorf("expected 2 Set-Cookie headers, got %d", len(setCookies))
	}
	for _, sc := range setCookies {
		if !strings.HasPrefix(sc, "session=;") && !strings.HasPrefix(sc, "csrf=;") {
			t.Errorf("unexpected cleared cookie header %q", sc)
		}
	}
}
