package main

import (
	"any-oidc-proxy/pkg/backend"
	"any-oidc-proxy/pkg/backend/metabase"
	"any-oidc-proxy/pkg/backend/nocodb"
	oidcauth "any-oidc-proxy/pkg/oidc"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

type App struct {
	oidcAuth      *oidcauth.OIDCAuthenticator
	backend       backend.Backend
	cookieManager backend.CookieManager
	config        *Config
}

func getBackend(cfg *Config) (backend.Backend, error) {
	switch cfg.Type {
	case "metabase":
		mbBackend, err := metabase.NewMetabaseBackend(
			cfg.ProxyURL,
			cfg.MetabaseAdminEmail,
			cfg.MetabaseAdminPassword,
			&http.Client{Timeout: cfg.HTTPRequestTimeoutBackend},
		)
		if err != nil {
			return nil, err
		}
		return mbBackend, nil
	case "nocodb":
		mbBackend, err := nocodb.NewNocodbBackend(
			cfg.ProxyURL,
			cfg.NocodbAdminEmail,
			cfg.NocodbAdminPassword,
			&http.Client{Timeout: cfg.HTTPRequestTimeoutBackend},
		)
		if err != nil {
			return nil, err
		}
		return mbBackend, nil
	default:
		return nil, errors.New("invalid backend type")
	}
}

func newApp(cfg *Config) (*App, error) {
	mbBackend, err := getBackend(cfg)
	// Менеджер куков
	cookieManager := backend.NewSimpleCookieManager(cfg.SecureCookies, cfg.MetabaseSessionCookieName)

	// OIDC аутентификатор
	redirectURL, err := url.JoinPath(cfg.ExternalURL, cfg.OIDCPath, "callback")
	if err != nil {
		return nil, err
	}

	oidcConfig := oidcauth.Config{
		IssuerURL:      cfg.OIDCIssuer,
		ClientID:       cfg.OIDCClientID,
		ClientSecret:   cfg.OIDCClientSecret,
		RedirectURL:    redirectURL,
		Scopes:         cfg.OIDCScope,
		StateSecret:    cfg.StateSecret,
		StateTTL:       cfg.StateTTL,
		AllowedDomains: cfg.AllowedEmailDomains,
	}

	oidcAuth, err := oidcauth.NewOIDCAuthenticator(oidcConfig, mbBackend, cookieManager)
	if err != nil {
		return nil, err
	}

	return &App{
		oidcAuth:      oidcAuth,
		backend:       mbBackend,
		cookieManager: cookieManager,
		config:        cfg,
	}, nil
}

func (a *App) handleOIDC(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("rd")
	if redirect == "" {
		redirect = r.Referer()
	}
	if redirect == "" {
		redirect = "/"
	}

	if err := a.oidcAuth.StartAuth(w, r, redirect); err != nil {
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
	}
}

func (a *App) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if err := a.oidcAuth.HandleCallback(w, r); err != nil {
		log.Printf("OIDC callback error: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
	}
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	startPath := a.config.OIDCPath
	callbackPath := strings.TrimSuffix(a.config.OIDCPath, "/") + "/callback"
	proxyURL, err := url.Parse(a.config.ProxyURL)
	if err != nil {
		log.Warnf("PROXY_URL parse: %w", err)
		return nil
	}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})

	// OIDC entry and callback
	mux.HandleFunc(startPath, a.handleOIDC)
	mux.HandleFunc(callbackPath, a.handleOIDCCallback)

	// Reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		// Fix forwarded headers
		if r.Header.Get("X-Forwarded-Proto") == "" {
			if r.TLS != nil {
				r.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Header.Set("X-Forwarded-Proto", "http")
			}
		}
		if r.Header.Get("X-Forwarded-Host") == "" {
			r.Header.Set("X-Forwarded-Host", r.Host)
		}
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			prior := r.Header.Get("X-Forwarded-For")
			if prior == "" {
				r.Header.Set("X-Forwarded-For", ip)
			} else {
				r.Header.Set("X-Forwarded-For", prior+", "+ip)
			}
		}
	}
	if a.config.ProxyRewriteLocationHeader {
		proxy.ModifyResponse = func(resp *http.Response) error {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil
			}
			if strings.HasPrefix(loc, a.config.ProxyURL) {
				newLoc := a.config.ExternalURL + strings.TrimPrefix(loc, a.config.ProxyURL)
				resp.Header.Set("Location", newLoc)
			}
			return nil
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		log.Printf("proxy error: %v", e)
		http.Error(w, "Upstream error", http.StatusBadGateway)
	}

	// everything else -> proxy
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	return mux
}

func (a *App) Start() {
	s := &http.Server{
		Addr:         a.config.ListenAddr,
		Handler:      a.routes(),
		ReadTimeout:  a.config.HTTPReadTimeout,
		WriteTimeout: a.config.HTTPWriteTimeout,
	}

	log.Printf(
		"Listening on %s; proxy -> %s; OIDC path: %s",
		a.config.ListenAddr,
		a.config.ProxyURL,
		a.config.OIDCPath,
	)
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}
