package plane

import (
	"any-oidc-proxy/pkg/backend"
	oidcauth "any-oidc-proxy/pkg/oidc"
	"context"
	"net/http"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PlaneBackend struct {
	db         *gorm.DB
	baseURL    string
	httpClient *http.Client
}

// NewPlaneBackend инициализирует соединение с базой данных.
func NewPlaneBackend(baseURL string, dsn string, httpClient *http.Client) (*PlaneBackend, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{}) // или используйте другой драйвер
	if err != nil {
		return nil, err
	}
	return &PlaneBackend{
		db:         db,
		baseURL:    baseURL,
		httpClient: httpClient,
	}, nil
}

func (pb *PlaneBackend) ProvisionUser(ctx context.Context, user backend.UserData) (string, error) {
	return user.Email, nil
}

func (pb *PlaneBackend) Login(ctx context.Context, userID string, userData backend.UserData) ([]string, error) {
	randomPwd := oidcauth.GenPassword(24)
	_, err := pb.createOrUpdateUser(
		userData.Email,
		userData.FirstName,
		userData.LastName,
		randomPwd,
	)
	if err != nil {
		return []string{}, err
	}
	log.Debugf("user: %s password: %s", userData.Email, randomPwd)
	cookies, err := pb.loginUser(ctx, userData.Email, randomPwd)
	if err != nil {
		log.Infof("Error on login user %+v", err)
		return []string{}, err
	}
	return cookies, nil
}
