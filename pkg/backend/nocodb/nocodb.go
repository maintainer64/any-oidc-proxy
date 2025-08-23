package nocodb

import (
	"any-oidc-proxy/pkg/backend"
	oidcauth "any-oidc-proxy/pkg/oidc"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	log "github.com/sirupsen/logrus"
)

type NocodbBackend struct {
	client *ClientOIDC
}

func NewNocodbBackend(baseURL, adminEmail, adminPassword string, httpClient *http.Client) (*NocodbBackend, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	client := &ClientOIDC{
		BaseURL:       u,
		AdminEmail:    adminEmail,
		AdminPassword: adminPassword,
		HTTP:          httpClient,
		AdminTokenMu:  &sync.Mutex{},
	}

	return &NocodbBackend{
		client: client,
	}, nil
}

func (m *NocodbBackend) ProvisionUser(ctx context.Context, user backend.UserData) (string, error) {
	randomPwd := oidcauth.GenPassword(24)
	userExternal, err := m.client.FindOrCreateUser(ctx, user.Email, user.FirstName, user.LastName, randomPwd)
	if err != nil {
		log.Printf("nocodb provision error: %v", err)
		return "", errors.New("nocodb provision failed")
	}
	return userExternal.ID, nil
}

func (m *NocodbBackend) Login(ctx context.Context, userID string, userData backend.UserData) ([]string, error) {
	randomPwd := oidcauth.GenPassword(24)
	token, err := m.client.PasswordGenerateResetUrl(ctx, userID)
	if err != nil {
		log.Printf("nocodb password reset error: %v", err)
		return nil, errors.New("nocodb password reset error")
	}
	err = m.client.PasswordSet(ctx, token, randomPwd)
	if err != nil {
		log.Printf("nocodb password set error: %v", err)
		return nil, errors.New("nocodb password set error")
	}
	sessionID, setCookies, err := m.client.LoginUser(ctx, userData.Email, randomPwd)
	if err != nil || sessionID == "" {
		log.Printf("nocodb login error: %v", err)
		return nil, errors.New("metabase login failed")
	}
	return setCookies, nil
}
