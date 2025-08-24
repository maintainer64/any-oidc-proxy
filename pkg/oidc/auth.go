package oidcauth

import (
	"any-oidc-proxy/pkg/backend"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCAuthenticator struct {
	config         *oauth2.Config
	verifier       *oidc.IDTokenVerifier
	backend        backend.Backend
	cookieManager  backend.CookieManager
	stateSecret    string
	stateTTL       time.Duration
	allowedDomains map[string]struct{}
	allowedEmails  map[string]struct{}
}

type Config struct {
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	RedirectURL    string
	Scopes         []string
	StateSecret    string
	StateTTL       time.Duration
	AllowedDomains []string
	AllowedEmails  []string
}

func NewOIDCAuthenticator(cfg Config, backend backend.Backend, cookieManager backend.CookieManager) (*OIDCAuthenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	allowed := make(map[string]struct{})
	for _, domain := range cfg.AllowedDomains {
		allowed[strings.ToLower(domain)] = struct{}{}
	}

	allowedEmails := make(map[string]struct{})
	for _, email := range cfg.AllowedEmails {
		allowedEmails[strings.ToLower(email)] = struct{}{}
	}

	return &OIDCAuthenticator{
		config:         oauthConfig,
		verifier:       verifier,
		backend:        backend,
		cookieManager:  cookieManager,
		stateSecret:    cfg.StateSecret,
		stateTTL:       cfg.StateTTL,
		allowedDomains: allowed,
		allowedEmails:  allowedEmails,
	}, nil
}

func (a *OIDCAuthenticator) StartAuth(w http.ResponseWriter, r *http.Request, redirectURL string) error {
	state, err := a.createState(redirectURL)
	if err != nil {
		return err
	}

	authURL := a.config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func (a *OIDCAuthenticator) HandleCallback(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Валидация state
	state := r.URL.Query().Get("state")
	redirectURL, err := a.validateState(state)
	if err != nil {
		return fmt.Errorf("invalid state: %w", err)
	}

	// Обмен кода на токен
	code := r.URL.Query().Get("code")
	token, err := a.config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}

	// Получение информации о пользователе
	userData, err := a.extractUserInfo(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}

	// Проверка домена email
	if err := a.validateEmailDomain(userData.Email); err != nil {
		return err
	}

	// Проверка email'ов
	if err := a.validateEmail(userData.Email); err != nil {
		return err
	}

	// Provision пользователя в бэкенде
	userID, err := a.backend.ProvisionUser(ctx, userData)
	if err != nil {
		return fmt.Errorf("failed to provision user: %w", err)
	}

	// Логин в бэкенде
	cookies, err := a.backend.Login(ctx, userID, userData)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}

	// Установка куков
	a.cookieManager.SetSessionCookies(w, r, cookies)

	// Редирект
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

func (a *OIDCAuthenticator) extractUserInfo(ctx context.Context, token *oauth2.Token) (backend.UserData, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return backend.UserData{}, fmt.Errorf("no id_token in token response")
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return backend.UserData{}, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		FamilyName        string `json:"family_name"`
		GivenName         string `json:"given_name"`
		PreferredUsername string `json:"preferred_username"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return backend.UserData{}, fmt.Errorf("failed to parse claims: %w", err)
	}

	lastName, firstName := a.splitName(claims.Name)

	userData := backend.UserData{
		Email:     claims.Email,
		FirstName: firstName,
		LastName:  lastName,
		Subject:   claims.Sub,
	}

	if claims.FamilyName != "" {
		userData.LastName = claims.FamilyName
	}

	if claims.GivenName != "" {
		userData.FirstName = claims.GivenName
	}

	return userData, nil
}

func (a *OIDCAuthenticator) splitName(fullName string) (string, string) {
	if fullName == "" {
		return "User", "OIDC"
	}

	parts := strings.Fields(fullName)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

func (a *OIDCAuthenticator) validateEmailDomain(email string) error {
	if len(a.allowedDomains) == 0 {
		return nil
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format")
	}

	domain := strings.ToLower(parts[1])
	if _, allowed := a.allowedDomains[domain]; !allowed {
		return fmt.Errorf("email domain not allowed")
	}

	return nil
}

func (a *OIDCAuthenticator) validateEmail(email string) error {
	if len(a.allowedEmails) == 0 {
		return nil
	}

	if _, allowed := a.allowedEmails[email]; !allowed {
		return fmt.Errorf("email not allowed")
	}

	return nil
}

// State management
func (a *OIDCAuthenticator) createState(redirectURL string) (string, error) {
	state := map[string]interface{}{
		"redirect": redirectURL,
		"ts":       time.Now().Unix(),
		"nonce":    uuid.New().String(),
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(a.stateSecret))
	mac.Write(stateJSON)
	signature := mac.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(stateJSON) + "." +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func (a *OIDCAuthenticator) validateState(rawState string) (string, error) {
	parts := strings.Split(rawState, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid state format")
	}

	stateJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid state encoding")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding")
	}

	mac := hmac.New(sha256.New, []byte(a.stateSecret))
	mac.Write(stateJSON)
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(signature, expectedSignature) {
		return "", fmt.Errorf("invalid state signature")
	}

	var state map[string]interface{}
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		return "", fmt.Errorf("invalid state JSON")
	}

	// Check expiration
	if ts, ok := state["ts"].(float64); ok {
		if time.Since(time.Unix(int64(ts), 0)) > a.stateTTL {
			return "", fmt.Errorf("state expired")
		}
	}

	redirect, ok := state["redirect"].(string)
	if !ok || redirect == "" {
		return "/", nil
	}

	return redirect, nil
}
