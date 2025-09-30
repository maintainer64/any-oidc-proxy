package zabbix

import (
	"any-oidc-proxy/pkg/backend"
	oidcauth "any-oidc-proxy/pkg/oidc"
	"context"
	"errors"
	log "github.com/sirupsen/logrus"
)

type OIDC struct {
	baseURL string
	client  *ZabbixClientRPC
}

// NewZabbixOIDC инициализирует соединение с базой данных.
func NewZabbixOIDC(baseURL string, token string) (*OIDC, error) {
	return &OIDC{
		baseURL: baseURL,
		client:  NewZabbixClientRPC(baseURL, token),
	}, nil
}

func (c *OIDC) ProvisionUser(ctx context.Context, user backend.UserData) (string, error) {
	return user.Email, nil
}

func (c *OIDC) Login(ctx context.Context, userID string, userData backend.UserData) ([]string, error) {
	cookies := make([]string, 0)
	roleName := "default::oidc"
	if len(userData.Groups) > 0 && userData.Groups[0] != "" {
		roleName = userData.Groups[0] + "::oidc"
	}
	// Get role
	role, err := c.client.RoleGet(ctx, roleName)
	if err != nil {
		log.Debugf("role get by name %s is error", roleName)
		return cookies, err
	}
	// Role create
	if role == nil {
		err := c.client.RoleCreate(ctx, roleName)
		if err != nil {
			log.Debugf("role create by name %s is error", roleName)
			return cookies, err
		}
		role, err = c.client.RoleGet(ctx, roleName)
		if err != nil {
			log.Debugf("role get by name %s is error", roleName)
			return cookies, err
		}
	}
	// Role not found
	if role == nil {
		log.Debugf("role get by name %s not found", roleName)
		return cookies, errors.New("role not found")
	}
	// User get
	userFromZabbix, err := c.client.UserGet(ctx, userData.Email)
	if err != nil {
		log.Debugf("users get by email %s error", userData.Email)
		return cookies, err
	}
	// User create
	if userFromZabbix == nil {
		err = c.client.UserCreate(ctx, userData.Email, userData.Name, role.RoleID)
		if err != nil {
			log.Debugf("user create by email %s is error", userData.Email)
			return cookies, err
		}
		userFromZabbix, err = c.client.UserGet(ctx, userData.Email)
		if err != nil {
			log.Debugf("users get by email %s error", userData.Email)
			return cookies, err
		}
	}
	// User not found
	if userFromZabbix == nil {
		log.Debugf("users get by email %s not found", userData.Email)
		return cookies, errors.New("user not found")
	}
	randomPwd := oidcauth.GenPassword(24)
	err = c.client.UserUpdate(
		ctx,
		userFromZabbix.UserID,
		userData.Name,
		role.RoleID,
		randomPwd,
	)
	if err != nil {
		log.Debugf("user update by email %s is error", userData.Email)
		return cookies, err
	}
	cookiesResponse, err := c.client.UserLogin(ctx, userData.Email, randomPwd)
	if err != nil {
		log.Debugf("user login by email %s is error", userData.Email)
		return cookies, err
	}
	if len(cookiesResponse) == 0 {
		log.Debugf("user session create by email %s is error", userData.Email)
		return cookies, errors.New("session not found")
	}
	return cookiesResponse, nil
}
