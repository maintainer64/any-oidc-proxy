package docmost

import (
	"context"
	"errors"
	"strings"
	"sync"

	"any-oidc-proxy/pkg/backend"
	oidcauth "any-oidc-proxy/pkg/oidc"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	errNoWorkspace  = errors.New("no workspace found: Docmost setup has not been run")
	ErrNotProvision = errors.New("docmost user not provisioned")
)

type DocmostBackend struct {
	db          *gorm.DB
	baseURL     string
	httpClient  backend.HTTPClient
	workspaceMu sync.Mutex
	workspaceID string
	// initial setup parameters (used once when no workspace exists)
	workspaceName string
	hostname      string
}

type Option func(*DocmostBackend)

func WithSetupParams(workspaceName, hostname string) Option {
	return func(d *DocmostBackend) {
		d.workspaceName = workspaceName
		d.hostname = hostname
	}
}

// NewDocmostBackend инициализирует соединение с базой данных Docmost.
func NewDocmostBackend(baseURL string, dsn string, httpClient backend.HTTPClient, opts ...Option) (*DocmostBackend, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	d := &DocmostBackend{
		db:            db,
		baseURL:       baseURL,
		httpClient:    httpClient,
		workspaceName: "Docs",
	}
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// getWorkspaceID возвращает идентификатор первого воркспейса (self-hosted:
// воркспейс один). Резолвится один раз и кэшируется.
func (d *DocmostBackend) getWorkspaceID() (string, error) {
	d.workspaceMu.Lock()
	defer d.workspaceMu.Unlock()

	if d.workspaceID != "" {
		return d.workspaceID, nil
	}
	var ws Workspace
	err := d.db.
		Where("deleted_at IS NULL").
		Order("created_at ASC").
		Limit(1).
		First(&ws).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", errNoWorkspace
		}
		return "", err
	}
	d.workspaceID = ws.ID
	return ws.ID, nil
}

func (d *DocmostBackend) ProvisionUser(ctx context.Context, user backend.UserData) (string, error) {
	if user.Email == "" {
		return "", ErrNotProvision
	}
	return strings.ToLower(user.Email), nil
}

// Login создаёт (или обновляет) пользователя в БД Docmost и выполняет вход
// через API, возвращая сессионные куки (authToken).
func (d *DocmostBackend) Login(ctx context.Context, userID string, userData backend.UserData) (*backend.UserRedirect, error) {
	resp := &backend.UserRedirect{}
	randomPwd := oidcauth.GenPassword(24)
	email := strings.ToLower(userData.Email)
	name := userData.Name
	if name == "" {
		name = strings.Split(email, "@")[0]
	}

	workspaceID, err := d.getWorkspaceID()
	switch {
	case err == nil:
		// Стандартный путь: upsert пользователя + логин через API
		if err := d.upsertUser(ctx, email, name, randomPwd, workspaceID); err != nil {
			log.Infof("docmost upsert user %s: %v", email, err)
			return resp, err
		}
	case errors.Is(err, errNoWorkspace):
		// Первый вход: воркспейса ещё нет — выполняем initial setup,
		// первый OIDC-пользователь становится владельцем.
		cookies, setupErr := d.setup(ctx, email, name, randomPwd)
		if setupErr == nil {
			resp.Cookies = cookies
			return resp, nil
		}
		log.Infof("docmost initial setup failed (workspace may have been created concurrently): %v", setupErr)
		// Кто-то уже создал воркспейс — пробуем обычный путь
		workspaceID, err = d.getWorkspaceID()
		if err != nil {
			return resp, err
		}
		if err := d.upsertUser(ctx, email, name, randomPwd, workspaceID); err != nil {
			log.Infof("docmost upsert user %s: %v", email, err)
			return resp, err
		}
	default:
		return resp, err
	}

	cookies, err := d.login(ctx, email, randomPwd)
	if err != nil {
		log.Infof("docmost login user %s: %v", email, err)
		return resp, err
	}
	resp.Cookies = cookies
	return resp, nil
}
