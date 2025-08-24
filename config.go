package main

import (
	"errors"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddr  string
	ExternalURL string
	Type        string
	ProxyURL    string
	// Metabase
	MetabaseAdminEmail        string
	MetabaseAdminPassword     string
	MetabaseSessionCookieName string
	// Nocodb
	NocodbAdminEmail    string
	NocodbAdminPassword string
	// Plane
	PlaneDSN string
	// OIDC
	OIDCIssuer                 string
	OIDCClientID               string
	OIDCClientSecret           string
	OIDCPath                   string
	OIDCScope                  []string
	OIDCPrompt                 string
	StateSecret                string
	StateTTL                   time.Duration
	SecureCookies              bool
	UserInfoCookieName         string
	SetUserInfoCookie          bool
	AllowedEmailDomains        []string // optional allowlist, comma-separated
	DefaultUserFirstName       string
	DefaultUserLastName        string
	HTTPReadTimeout            time.Duration
	HTTPWriteTimeout           time.Duration
	HTTPRequestTimeoutBackend  time.Duration
	ProxyRewriteLocationHeader bool
	LogLevel                   string
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "y", "on":
			return true
		case "0", "false", "no", "n", "off":
			return false
		}
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getenvCSV(key string) []string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ListenAddr:  getenv("LISTEN_ADDR", ":8080"),
		ExternalURL: os.Getenv("EXTERNAL_URL"),
		Type:        os.Getenv("TYPE"),
		ProxyURL:    os.Getenv("PROXY_URL"),
		// Metabase
		MetabaseAdminEmail:        os.Getenv("METABASE_ADMIN_EMAIL"),
		MetabaseAdminPassword:     os.Getenv("METABASE_ADMIN_PASSWORD"),
		MetabaseSessionCookieName: getenv("METABASE_SESSION_COOKIE_NAME", "metabase.SESSION"),
		// Nocodb
		NocodbAdminEmail:    os.Getenv("NOCODB_ADMIN_EMAIL"),
		NocodbAdminPassword: os.Getenv("NOCODB_ADMIN_PASSWORD"),
		// Plane
		PlaneDSN: os.Getenv("PLANE_DSN"),
		// OIDC
		OIDCIssuer:                 os.Getenv("OIDC_ISSUER"),
		OIDCClientID:               os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:           os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCPath:                   getenv("OIDC_PATH", "/openid/"),
		OIDCScope:                  getenvCSV("OIDC_SCOPE"),
		OIDCPrompt:                 getenv("OIDC_PROMPT", ""),
		StateSecret:                os.Getenv("STATE_SECRET"),
		StateTTL:                   getenvDuration("STATE_TTL", 10*time.Minute),
		SecureCookies:              getenvBool("SECURE_COOKIES", true),
		UserInfoCookieName:         getenv("USERINFO_COOKIE_NAME", "oidc_user"),
		SetUserInfoCookie:          getenvBool("SET_USERINFO_COOKIE", true),
		AllowedEmailDomains:        getenvCSV("ALLOWED_EMAIL_DOMAINS"),
		DefaultUserFirstName:       getenv("DEFAULT_USER_FIRST_NAME", "User"),
		DefaultUserLastName:        getenv("DEFAULT_USER_LAST_NAME", "OIDC"),
		HTTPReadTimeout:            getenvDuration("HTTP_READ_TIMEOUT", 15*time.Second),
		HTTPWriteTimeout:           getenvDuration("HTTP_WRITE_TIMEOUT", 60*time.Second),
		HTTPRequestTimeoutBackend:  getenvDuration("HTTP_BACKEND_TIMEOUT", 60*time.Second),
		ProxyRewriteLocationHeader: getenvBool("PROXY_REWRITE_LOCATION", true),
		LogLevel:                   getenv("LOG_LEVEL", "info"),
	}

	if cfg.ExternalURL == "" ||
		cfg.OIDCIssuer == "" ||
		cfg.OIDCClientID == "" ||
		cfg.OIDCClientSecret == "" ||
		cfg.StateSecret == "" {
		return nil, errors.New("missing required ENV: EXTERNAL_URL, METABASE_URL, METABASE_ADMIN_EMAIL, METABASE_ADMIN_PASSWORD, OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, STATE_SECRET")
	}

	// Normalize OIDC path
	if !strings.HasPrefix(cfg.OIDCPath, "/") {
		cfg.OIDCPath = "/" + cfg.OIDCPath
	}
	if !strings.HasSuffix(cfg.OIDCPath, "/") {
		cfg.OIDCPath = cfg.OIDCPath + "/"
	}
	if len(cfg.OIDCScope) == 0 {
		cfg.OIDCScope = []string{"openid", "email", "profile"}
	}
	if cfg.ProxyURL == "" {
		return nil, errors.New("missing required ENV by metabase: PROXY_URL")
	}
	if cfg.Type == "metabase" && (cfg.MetabaseAdminEmail == "" ||
		cfg.MetabaseAdminPassword == "") {
		return nil, errors.New("missing required ENV by metabase: METABASE_ADMIN_EMAIL, METABASE_ADMIN_PASSWORD")
	}
	if cfg.Type == "nocodb" && (cfg.NocodbAdminEmail == "" ||
		cfg.NocodbAdminPassword == "") {
		return nil, errors.New("missing required ENV by metabase: NOCODB_ADMIN_EMAIL, NOCODB_ADMIN_PASSWORD")
	}
	if cfg.Type == "plane" && cfg.PlaneDSN == "" {
		return nil, errors.New("missing required ENV by metabase: PLANE_DSN")
	}
	return cfg, nil
}
