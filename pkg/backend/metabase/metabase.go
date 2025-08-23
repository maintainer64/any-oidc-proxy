package metabase

import (
	"any-oidc-proxy/pkg/backend"
	oidcauth "any-oidc-proxy/pkg/oidc"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
)

type MetabaseBackend struct {
	client *ClientOIDC
}

func NewMetabaseBackend(baseURL, adminEmail, adminPassword string, httpClient *http.Client) (*MetabaseBackend, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	client := &ClientOIDC{
		BaseURL:        u,
		AdminEmail:     adminEmail,
		AdminPassword:  adminPassword,
		HTTP:           httpClient,
		AdminSessionMu: &sync.Mutex{},
	}

	return &MetabaseBackend{
		client: client,
	}, nil
}

func (m *MetabaseBackend) ProvisionUser(ctx context.Context, user backend.UserData) (string, error) {
	randomPwd := oidcauth.GenPassword(24)
	userExternal, err := m.client.FindOrCreateUser(ctx, user.Email, user.FirstName, user.LastName, randomPwd)
	if err != nil {
		log.Printf("metabase provision error: %v", err)
		return "", errors.New("metabase provision failed")
	}
	_ = m.client.UpdateUser(ctx, userExternal.ID, map[string]any{
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
	})
	_ = m.client.ReactivateUser(ctx, userExternal.ID)
	return fmt.Sprintf("%d", userExternal.ID), nil
}

func (m *MetabaseBackend) Login(ctx context.Context, userID string, userData backend.UserData) ([]string, error) {
	randomPwd := oidcauth.GenPassword(24)
	userExternalId, err := strconv.Atoi(userID)
	if err != nil {
		log.Fatalf("Error converting string to int: %v", err)
		return nil, errors.New("invalid user id")
	}
	if err := m.client.ResetPassword(ctx, userExternalId, randomPwd); err != nil {
		// Best-effort: if reset endpoint differs by version, try update fallback already done internally
		log.Printf("password reset warning: %v", err)
	}

	sessionID, setCookies, err := m.client.LoginUser(ctx, userData.Email, randomPwd)
	if err != nil || sessionID == "" {
		log.Printf("metabase login error: %v", err)
		return nil, errors.New("metabase login failed")
	}
	return setCookies, nil
}
