package zabbix

import (
	"any-oidc-proxy/pkg/rpc"
	"context"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
)

type ZabbixClientRPC struct {
	client   *rpc.RPCClient
	urlLogin string
}

func NewZabbixClientRPC(baseUrl, token string) *ZabbixClientRPC {
	return &ZabbixClientRPC{
		client: rpc.NewRPCClient(
			baseUrl+"/api_jsonrpc.php",
			rpc.WithHeader("Authorization", fmt.Sprintf("Bearer %s", token)),
		),
		urlLogin: baseUrl + "/index.php",
	}
}

type UserZabbix struct {
	UserID string `json:"userid"`
}

func (c *ZabbixClientRPC) UserGet(ctx context.Context, username string) (*UserZabbix, error) {
	var result []UserZabbix
	params := map[string]interface{}{
		"output": "extend",
		"filter": map[string]interface{}{
			"username": username,
		},
	}
	err := c.client.Call(ctx, "user.get", params, &result)
	if err != nil {
		return nil, err
	}
	if len(result) > 0 {
		return &result[0], nil
	}
	return nil, nil
}

type RoleZabbix struct {
	RoleID string `json:"roleid"`
}

func (c *ZabbixClientRPC) RoleGet(ctx context.Context, name string) (*RoleZabbix, error) {
	var result []RoleZabbix
	params := map[string]interface{}{
		"output":   "extend",
		"editable": true,
		"filter": map[string]interface{}{
			"name": name,
		},
	}
	err := c.client.Call(ctx, "role.get", params, &result)
	if err != nil {
		return nil, err
	}
	if len(result) > 0 {
		return &result[0], nil
	}
	return nil, err
}

func (c *ZabbixClientRPC) RoleCreate(ctx context.Context, name string) error {
	var result interface{}
	params := map[string]string{
		"name": name,
		"type": "1",
	}
	err := c.client.Call(ctx, "role.create", params, &result)
	return err
}

type GroupZabbix struct {
	GroupID string `json:"usrgrpid"`
}

func (c *ZabbixClientRPC) GroupGet(ctx context.Context, name string) (*GroupZabbix, error) {
	var result []GroupZabbix
	params := map[string]interface{}{
		"output": "extend",
		"filter": map[string]interface{}{
			"name": name,
		},
	}
	err := c.client.Call(ctx, "usergroup.get", params, &result)
	if err != nil {
		return nil, err
	}
	if len(result) > 0 {
		return &result[0], nil
	}
	return nil, err
}

func (c *ZabbixClientRPC) GroupCreate(ctx context.Context, name string) error {
	var result interface{}
	params := map[string]string{
		"name": name,
	}
	err := c.client.Call(ctx, "usergroup.create", params, &result)
	return err
}

func (c *ZabbixClientRPC) UserCreate(ctx context.Context, username, name, roleID string) error {
	var result interface{}
	passwd := uuid.New().String()
	params := map[string]interface{}{
		"username":   username,
		"name":       name,
		"roleid":     roleID,
		"passwd":     passwd,
		"autologout": "15m",
	}
	err := c.client.Call(ctx, "user.create", params, &result)
	return err
}

func (c *ZabbixClientRPC) UserUpdate(ctx context.Context, userid, name, roleID, groupID, randomPwd string) error {
	var result interface{}
	params := map[string]interface{}{
		"userid": userid,
		"name":   name,
		"roleid": roleID,
		"usrgrps": []interface{}{
			map[string]interface{}{
				"usrgrpid": groupID,
			},
		},
		"passwd":     randomPwd,
		"autologout": "15m",
	}
	err := c.client.Call(ctx, "user.update", params, &result)
	return err
}

func (c *ZabbixClientRPC) UserLogin(ctx context.Context, username, password string) ([]string, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Disable automatic redirects
		},
	}
	form := url.Values{}
	form.Set("name", username)
	form.Set("password", password)
	form.Set("enter", "Войти")
	request, _ := http.NewRequestWithContext(ctx, "POST", c.urlLogin, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return []string{}, fmt.Errorf("zabbix error login: %w", err)
	}
	defer response.Body.Close()
	cookies := response.Header.Values("Set-Cookie")
	log.Debugf(
		"user login %s by password url: %s, response cookies %+v, status %d",
		username,
		c.urlLogin,
		cookies,
		response.StatusCode,
	)
	return cookies, err
}
