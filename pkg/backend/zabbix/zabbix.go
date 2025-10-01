package zabbix

import (
	"any-oidc-proxy/pkg/backend"
	oidcauth "any-oidc-proxy/pkg/oidc"
	"context"
	"errors"
	log "github.com/sirupsen/logrus"
)

const OIDCGroup = "oidc"

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

func (c *OIDC) Login(ctx context.Context, userID string, userData backend.UserData) (*backend.UserRedirect, error) {
	resp := &backend.UserRedirect{
		RedirectLocation: "/zabbix.php?action=dashboard.view",
	}
	roleName := "default::" + OIDCGroup
	if len(userData.Groups) > 0 && userData.Groups[0] != "" {
		roleName = userData.Groups[0] + "::" + OIDCGroup
	}
	// Role get
	role, err := c.client.RoleGet(ctx, roleName)
	if err != nil {
		log.Debugf("role get by name %s is error", roleName)
		return resp, err
	}
	// Role create
	if role == nil {
		err := c.client.RoleCreate(ctx, roleName)
		if err != nil {
			log.Debugf("role create by name %s is error", roleName)
			return resp, err
		}
		role, err = c.client.RoleGet(ctx, roleName)
		if err != nil {
			log.Debugf("role get by name %s is error", roleName)
			return resp, err
		}
	}
	// Role not found
	if role == nil {
		log.Debugf("role get by name %s not found", roleName)
		return resp, errors.New("role not found")
	}
	// Group get
	group, err := c.client.GroupGet(ctx, OIDCGroup)
	if err != nil {
		log.Debugf("group create by name %s is error", OIDCGroup)
		return resp, err
	}
	// Group create
	if group == nil {
		err := c.client.GroupCreate(ctx, OIDCGroup)
		if err != nil {
			log.Debugf("group create by name %s is error", OIDCGroup)
			return resp, err
		}
		group, err = c.client.GroupGet(ctx, OIDCGroup)
		if err != nil {
			log.Debugf("group get by name %s is error", OIDCGroup)
			return resp, err
		}
	}
	if group == nil {
		log.Debugf("group get by name %s not found", OIDCGroup)
		return resp, errors.New("group not found")
	}
	// User get
	userFromZabbix, err := c.client.UserGet(ctx, userData.Email)
	if err != nil {
		log.Debugf("users get by email %s error", userData.Email)
		return resp, err
	}
	// User create
	if userFromZabbix == nil {
		err = c.client.UserCreate(ctx, userData.Email, userData.Name, role.RoleID)
		if err != nil {
			log.Debugf("user create by email %s is error", userData.Email)
			return resp, err
		}
		userFromZabbix, err = c.client.UserGet(ctx, userData.Email)
		if err != nil {
			log.Debugf("users get by email %s error", userData.Email)
			return resp, err
		}
	}
	// User not found
	if userFromZabbix == nil {
		log.Debugf("users get by email %s not found", userData.Email)
		return resp, errors.New("user not found")
	}
	randomPwd := oidcauth.GenPassword(24)
	err = c.client.UserUpdate(
		ctx,
		userFromZabbix.UserID,
		userData.Name,
		role.RoleID,
		group.GroupID,
		randomPwd,
	)
	if err != nil {
		log.Debugf("user update by email %s is error", userData.Email)
		return resp, err
	}
	cookiesResponse, err := c.client.UserLogin(ctx, userData.Email, randomPwd)
	if err != nil {
		log.Debugf("user login by email %s is error", userData.Email)
		return resp, err
	}
	if len(cookiesResponse) == 0 {
		log.Debugf("user session create by email %s is error", userData.Email)
		return resp, errors.New("session not found")
	}
	resp.Cookies = cookiesResponse
	return resp, nil
}
