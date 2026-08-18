package main

import (
	"strings"
	"testing"
	"time"
)

const testExternalURL = "https://docs.gubanov.site"

func setBaseEnv(t *testing.T) {
	t.Helper()
	// Сброс переменных, которые могут быть выставлены во внешнем окружении
	for _, k := range []string{
		"LISTEN_ADDR", "OIDC_PATH", "OIDC_SCOPE", "OIDC_PROMPT", "STATE_TTL",
		"SECURE_COOKIES", "SET_USERINFO_COOKIE", "COOKIES", "USERINFO_COOKIE_NAME",
		"ALLOWED_EMAIL_DOMAINS", "ALLOWED_EMAILS", "DOCMOST_WORKSPACE_NAME",
		"DOCMOST_HOSTNAME", "LOG_LEVEL", "PROXY_REWRITE_LOCATION",
		"HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_BACKEND_TIMEOUT",
		"DEFAULT_USER_FIRST_NAME", "DEFAULT_USER_LAST_NAME", "METABASE_URL",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("EXTERNAL_URL", testExternalURL)
	t.Setenv("PROXY_URL", "http://docmost:3000")
	t.Setenv("TYPE", "docmost")
	t.Setenv("DOCMOST_DSN", "postgresql://docmost:pw@db:5432/docmost")
	t.Setenv("OIDC_ISSUER", "https://auth.gubanov.site")
	t.Setenv("OIDC_CLIENT_ID", "docmost")
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	t.Setenv("STATE_SECRET", "state-secret")
}

func TestLoadConfigDefaults(t *testing.T) {
	setBaseEnv(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("listen addr = %q", cfg.ListenAddr)
	}
	if cfg.OIDCPath != "/openid/" {
		t.Errorf("oidc path = %q", cfg.OIDCPath)
	}
	if len(cfg.OIDCScope) != 3 || cfg.OIDCScope[0] != "openid" {
		t.Errorf("scope = %v", cfg.OIDCScope)
	}
	if !cfg.SecureCookies {
		t.Error("secure cookies should default to true")
	}
	if cfg.DocmostWorkspaceName != "Docs" {
		t.Errorf("docmost workspace = %q", cfg.DocmostWorkspaceName)
	}
	if cfg.StateTTL != 10*time.Minute {
		t.Errorf("state ttl = %v", cfg.StateTTL)
	}
	if !cfg.ProxyRewriteLocationHeader {
		t.Error("proxy rewrite location should default to true")
	}
}

func TestLoadConfigNormalizesOIDCPath(t *testing.T) {
	setBaseEnv(t)
	for _, in := range []string{"openid", "openid/", "/oidc", "/oidc/"} {
		t.Setenv("OIDC_PATH", in)
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig(%q): %v", in, err)
		}
		if cfg.OIDCPath != "/"+strings.Trim(in, "/")+"/" {
			t.Errorf("OIDC_PATH=%q → %q", in, cfg.OIDCPath)
		}
	}
}

func TestLoadConfigParsesCSVAndBool(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("ALLOWED_EMAIL_DOMAINS", " gubanov.site, example.com ,")
	t.Setenv("COOKIES", "authToken,session")
	t.Setenv("SECURE_COOKIES", "off")
	t.Setenv("SET_USERINFO_COOKIE", "false")
	t.Setenv("OIDC_SCOPE", "openid,email")
	t.Setenv("STATE_TTL", "5m")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.AllowedEmailDomains) != 2 || cfg.AllowedEmailDomains[0] != "gubanov.site" || cfg.AllowedEmailDomains[1] != "example.com" {
		t.Errorf("domains = %v", cfg.AllowedEmailDomains)
	}
	if len(cfg.SessionCookieNames) != 2 {
		t.Errorf("cookie names = %v", cfg.SessionCookieNames)
	}
	if cfg.SecureCookies {
		t.Error("secure cookies should be off")
	}
	if cfg.SetUserInfoCookie {
		t.Error("userinfo cookie should be off")
	}
	if len(cfg.OIDCScope) != 2 || cfg.OIDCScope[1] != "email" {
		t.Errorf("scope = %v", cfg.OIDCScope)
	}
	if cfg.StateTTL != 5*time.Minute {
		t.Errorf("state ttl = %v", cfg.StateTTL)
	}
}

func TestLoadConfigMissingRequired(t *testing.T) {
	t.Setenv("TYPE", "docmost")
	t.Setenv("DOCMOST_DSN", "x")
	for _, key := range []string{"EXTERNAL_URL", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "STATE_SECRET"} {
		t.Setenv(key, "")
		_, err := loadConfig()
		if err == nil {
			t.Errorf("expected error with %s missing", key)
		}
		t.Setenv(key, "set")
	}
}

func TestLoadConfigTypeValidation(t *testing.T) {
	cases := []struct {
		typ      string
		validEnv func()
		missing  string
	}{
		{"metabase", func() {
			t.Setenv("METABASE_ADMIN_EMAIL", "a@b.c")
			t.Setenv("METABASE_ADMIN_PASSWORD", "pw")
		}, "METABASE_ADMIN_EMAIL"},
		{"nocodb", func() {
			t.Setenv("NOCODB_ADMIN_EMAIL", "a@b.c")
			t.Setenv("NOCODB_ADMIN_PASSWORD", "pw")
		}, "NOCODB_ADMIN_EMAIL"},
		{"plane", func() { t.Setenv("PLANE_DSN", "postgres://x") }, "PLANE_DSN"},
		{"zabbix", func() { t.Setenv("ZABBIX_TOKEN", "tok") }, "ZABBIX_TOKEN"},
		{"docmost", func() { t.Setenv("DOCMOST_DSN", "postgres://x") }, "DOCMOST_DSN"},
	}

	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			setBaseEnv(t)
			t.Setenv("TYPE", tc.typ)
			tc.validEnv()

			// Валидная конфигурация
			if _, err := loadConfig(); err != nil {
				t.Fatalf("valid config rejected: %v", err)
			}
			// Отсутствие специфичной переменной → ошибка
			t.Setenv(tc.missing, "")
			_, err := loadConfig()
			if err == nil {
				t.Errorf("expected error with %s missing", tc.missing)
			}
			if !strings.Contains(errString(err), tc.missing) {
				t.Errorf("error should mention %s", tc.missing)
			}
		})
	}
}

func TestLoadConfigMissingProxyURL(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("PROXY_URL", "")
	_, err := loadConfig()
	if err == nil || !strings.Contains(err.Error(), "PROXY_URL") {
		t.Errorf("expected PROXY_URL error, got %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
