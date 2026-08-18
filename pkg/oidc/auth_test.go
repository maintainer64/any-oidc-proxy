package oidcauth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"any-oidc-proxy/pkg/backend"
	oidcauth "any-oidc-proxy/pkg/oidc"
)

// ---- mock OIDC provider ----

type mockProvider struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	clientID       string
	clientSecret   string
	issuer         string
	authorizeCalls []url.Values
	tokenCalls     int
}

func newMockProvider(t *testing.T, clientID, clientSecret string) *mockProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	mp := &mockProvider{key: key, clientID: clientID, clientSecret: clientSecret}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                mp.issuer,
			"authorization_endpoint":                mp.issuer + "/authorize",
			"token_endpoint":                        mp.issuer + "/token",
			"jwks_uri":                              mp.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := mp.key.Public().(*rsa.PublicKey)
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key",
				"e": e, "n": n,
			}},
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		mp.authorizeCalls = append(mp.authorizeCalls, q)
		redirectURI := q.Get("redirect_uri")
		if redirectURI == "" {
			http.Error(w, "missing redirect_uri", http.StatusBadRequest)
			return
		}
		u, _ := url.Parse(redirectURI)
		uq := u.Query()
		uq.Set("code", "auth-code-123")
		uq.Set("state", q.Get("state"))
		u.RawQuery = uq.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		mp.tokenCalls++
		r.ParseForm()
		mp.serveToken(w, r)
	})

	mp.server = httptest.NewServer(mux)
	mp.issuer = mp.server.URL
	t.Cleanup(mp.server.Close)
	return mp
}

func (mp *mockProvider) serveToken(w http.ResponseWriter, r *http.Request) {
	gotID := r.Form.Get("client_id")
	gotSecret := r.Form.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		gotID, gotSecret = u, p
	}
	if gotID != mp.clientID || gotSecret != mp.clientSecret {
		http.Error(w, "bad client credentials", http.StatusUnauthorized)
		return
	}
	code := r.Form.Get("code")
	if code != "auth-code-123" {
		http.Error(w, "bad code", http.StatusBadRequest)
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss":    mp.issuer,
		"sub":    "user-sub-42",
		"aud":    mp.clientID,
		"exp":    now.Add(10 * time.Minute).Unix(),
		"iat":    now.Unix(),
		"email":  "ivan@gubanov.site",
		"name":   "Ivan Ivanov",
		"groups": []string{"docs"},
	}
	idToken, err := mp.sign(claims)
	if err != nil {
		http.Error(w, "sign error", http.StatusInternalServerError)
		return
	}
	// важно: Go не распознаёт JSON при content-type sniffing (text/plain),
	// а oauth2 парсит text/plain как form-urlencoded
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "access-token-1",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (mp *mockProvider) sign(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"}
	encode := func(v any) (string, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	h, _ := encode(header)
	p, _ := encode(claims)
	signingInput := h + "." + p
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, mp.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ---- fake backend ----

type fakeBackend struct {
	provisioned []backend.UserData
	loggedIn    []string
	loginErr    error
}

func (f *fakeBackend) ProvisionUser(ctx context.Context, u backend.UserData) (string, error) {
	f.provisioned = append(f.provisioned, u)
	return strings.ToLower(u.Email), nil
}

func (f *fakeBackend) Login(ctx context.Context, userID string, u backend.UserData) (*backend.UserRedirect, error) {
	f.loggedIn = append(f.loggedIn, userID)
	if f.loginErr != nil {
		return nil, f.loginErr
	}
	return &backend.UserRedirect{Cookies: []string{
		"authToken=session-abc; HttpOnly; Path=/",
		"access_token=access-token-1; Path=/",
	}}, nil
}

// ---- helpers ----

func newTestAuthenticator(t *testing.T, mp *mockProvider, allowedDomains []string) *oidcauth.OIDCAuthenticator {
	t.Helper()
	return mustAuth(t, oidcauth.Config{
		IssuerURL:      mp.issuer,
		ClientID:       mp.clientID,
		ClientSecret:   mp.clientSecret,
		RedirectURL:    "https://docs.gubanov.site/oidc/callback",
		Scopes:         []string{"openid", "email", "profile", "groups"},
		StateSecret:    "test-state-secret",
		StateTTL:       5 * time.Minute,
		AllowedDomains: allowedDomains,
	}, &fakeBackend{})
}

func mustAuth(t *testing.T, cfg oidcauth.Config, fb *fakeBackend) *oidcauth.OIDCAuthenticator {
	t.Helper()
	auth, err := oidcauth.NewOIDCAuthenticator(cfg, fb, backend.NewSimpleCookieManager(false, []string{
		"authToken", "access_token", "refresh_token",
	}))
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}
	return auth
}

func startAuth(t *testing.T, auth *oidcauth.OIDCAuthenticator, mp *mockProvider) (state, redirectURI string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://docs.gubanov.site/oidc", nil)
	rec := httptest.NewRecorder()
	if err := auth.StartAuth(rec, req, "/dashboard"); err != nil {
		t.Fatalf("StartAuth: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("StartAuth status = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", rec.Header().Get("Location"), err)
	}
	q := loc.Query()
	if q.Get("redirect_uri") != "https://docs.gubanov.site/oidc/callback" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("client_id") != mp.clientID {
		t.Fatalf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type = %q", q.Get("response_type"))
	}
	return q.Get("state"), loc.String()
}

func callback(t *testing.T, auth *oidcauth.OIDCAuthenticator, state string) *httptest.ResponseRecorder {
	t.Helper()
	cb := "https://docs.gubanov.site/oidc/callback?code=auth-code-123&state=" + url.QueryEscape(state)
	req := httptest.NewRequest(http.MethodGet, cb, nil)
	rec := httptest.NewRecorder()
	err := auth.HandleCallback(rec, req)
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	return rec
}

// ---- tests ----

func TestOIDCFullFlow(t *testing.T) {
	mp := newMockProvider(t, "docmost", "secret")
	fb := &fakeBackend{}
	auth := mustAuth(t, oidcauth.Config{
		IssuerURL:      mp.issuer,
		ClientID:       mp.clientID,
		ClientSecret:   mp.clientSecret,
		RedirectURL:    "https://docs.gubanov.site/oidc/callback",
		Scopes:         []string{"openid", "email", "profile"},
		StateSecret:    "test-state-secret",
		StateTTL:       5 * time.Minute,
		AllowedDomains: []string{"gubanov.site"},
	}, fb)

	state, _ := startAuth(t, auth, mp)
	if state == "" {
		t.Fatal("state пустой")
	}

	rec := callback(t, auth, state)

	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("final redirect = %q, want /dashboard", loc)
	}

	if len(fb.provisioned) != 1 {
		t.Fatalf("provisioned = %d calls, want 1", len(fb.provisioned))
	}
	u := fb.provisioned[0]
	if u.Email != "ivan@gubanov.site" {
		t.Errorf("email = %q", u.Email)
	}
	if u.Subject != "user-sub-42" {
		t.Errorf("subject = %q", u.Subject)
	}
	if len(fb.loggedIn) != 1 || fb.loggedIn[0] != "ivan@gubanov.site" {
		t.Errorf("loggedIn = %v", fb.loggedIn)
	}

	// куки из бэкенда переписаны на host запроса
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case "authToken":
			if c.Value != "session-abc" {
				t.Errorf("authToken value = %q", c.Value)
			}
		case "access_token":
			if c.Value != "access-token-1" {
				t.Errorf("access_token value = %q", c.Value)
			}
		default:
			t.Errorf("unexpected cookie %q", c.Name)
		}
	}
	if mp.tokenCalls != 1 {
		t.Errorf("token endpoint calls = %d, want 1", mp.tokenCalls)
	}
}

func TestOIDCRejectsDisallowedDomain(t *testing.T) {
	mp := newMockProvider(t, "docmost", "secret")
	fb := &fakeBackend{}
	auth := mustAuth(t, oidcauth.Config{
		IssuerURL:      mp.issuer,
		ClientID:       mp.clientID,
		ClientSecret:   mp.clientSecret,
		RedirectURL:    "https://docs.gubanov.site/oidc/callback",
		Scopes:         []string{"openid", "email", "profile"},
		StateSecret:    "test-state-secret",
		StateTTL:       5 * time.Minute,
		AllowedDomains: []string{"other-domain.com"},
	}, fb)

	state, _ := startAuth(t, auth, mp)
	if err := auth.HandleCallback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
		"https://docs.gubanov.site/oidc/callback?code=auth-code-123&state="+url.QueryEscape(state), nil)); err == nil {
		t.Fatal("ожидалась ошибка для запрещённого домена")
	}
	if len(fb.provisioned) != 0 {
		t.Error("пользователь не должен уходить в backend при запрещённом домене")
	}
}

func TestOIDCRejectsTamperedState(t *testing.T) {
	mp := newMockProvider(t, "docmost", "secret")
	auth := newTestAuthenticator(t, mp, []string{"gubanov.site"})

	err := auth.HandleCallback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
		"https://docs.gubanov.site/oidc/callback?code=x&state=forged", nil))
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("err = %v, want state error", err)
	}
}

func TestOIDCFlowWithoutDomainRestriction(t *testing.T) {
	mp := newMockProvider(t, "docmost", "secret")
	fb := &fakeBackend{}
	auth := mustAuth(t, oidcauth.Config{
		IssuerURL:    mp.issuer,
		ClientID:     mp.clientID,
		ClientSecret: mp.clientSecret,
		RedirectURL:  "https://docs.gubanov.site/oidc/callback",
		Scopes:       []string{"openid", "email", "profile"},
		StateSecret:  "test-state-secret",
		StateTTL:     5 * time.Minute,
	}, fb)

	state, _ := startAuth(t, auth, mp)
	rec := callback(t, auth, state)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if len(fb.loggedIn) != 1 {
		t.Fatalf("loggedIn = %d, want 1", len(fb.loggedIn))
	}
}
