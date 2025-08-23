package nocodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ClientOIDC struct {
	BaseURL       *url.URL
	AdminEmail    string
	AdminPassword string
	HTTP          *http.Client

	AdminToken    string
	AdminTokenMu  *sync.Mutex
	AdminTokenExp time.Time
}

type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	InviteToken string `json:"invite_token"`
	Roles       string `json:"roles"`
}

type UserList struct {
	List     []User `json:"list"`
	PageInfo struct {
		TotalRows int `json:"totalRows"`
	} `json:"pageInfo"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

type ResetPasswordToken struct {
	ResetPasswordToken string `json:"reset_password_token"`
}

func (c *ClientOIDC) ensureAdmin(ctx context.Context) error {
	c.AdminTokenMu.Lock()
	defer c.AdminTokenMu.Unlock()

	// If token is valid, return
	if c.AdminToken != "" && time.Now().Before(c.AdminTokenExp) {
		return nil
	}

	// Login to get admin token
	loginURL := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/auth/user/signin"})
	body := map[string]string{
		"email":    c.AdminEmail,
		"password": c.AdminPassword,
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL.String(), strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin login failed: %s", strings.TrimSpace(string(b)))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return err
	}

	if authResp.Token == "" {
		return errors.New("empty admin token")
	}

	c.AdminToken = authResp.Token
	c.AdminTokenExp = time.Now().Add(8 * time.Hour)
	return nil
}

func (c *ClientOIDC) doJSON(
	ctx context.Context,
	method string,
	urlPath *url.URL,
	in any,
) (*http.Response, error) {
	if err := c.ensureAdmin(ctx); err != nil {
		return nil, err
	}

	u := c.BaseURL.ResolveReference(urlPath)
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = strings.NewReader(string(b))
	}

	req, _ := http.NewRequestWithContext(ctx, method, u.String(), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("xc-auth", c.AdminToken)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle expired token (401)
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		// reset and retry once
		c.AdminTokenMu.Lock()
		c.AdminToken = ""
		c.AdminTokenExp = time.Time{}
		c.AdminTokenMu.Unlock()

		if err := c.ensureAdmin(ctx); err != nil {
			return nil, err
		}

		req, _ = http.NewRequestWithContext(ctx, method, u.String(), body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("xc-auth", c.AdminToken)
		return c.HTTP.Do(req)
	}

	return resp, nil
}

func (c *ClientOIDC) ListUsersByEmail(ctx context.Context, email string) (*UserList, error) {
	resp, err := c.doJSON(
		ctx,
		http.MethodGet,
		&url.URL{Path: "/api/v1/users", RawQuery: fmt.Sprintf("query=%s", email)},
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list users failed: %s", strings.TrimSpace(string(b)))
	}

	var userList UserList
	if err := json.NewDecoder(resp.Body).Decode(&userList); err != nil {
		return nil, err
	}

	return &userList, nil
}

func (c *ClientOIDC) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	users, err := c.ListUsersByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if users == nil || len(users.List) == 0 {
		return nil, errors.New("no users found")
	}

	for _, u := range users.List {
		if strings.EqualFold(strings.TrimSpace(u.Email), strings.TrimSpace(email)) {
			return &u, nil
		}
	}

	return nil, nil
}

func (c *ClientOIDC) CreateUser(ctx context.Context, email, first, last, password string) (*User, error) {
	body := map[string]any{
		"email":     email,
		"firstname": first,
		"lastname":  last,
		"password":  password,
		"roles":     "org-level-creator",
	}

	resp, err := c.doJSON(ctx, http.MethodPost, &url.URL{Path: "/api/v1/users"}, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create user failed: %s", strings.TrimSpace(string(b)))
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (c *ClientOIDC) PasswordGenerateResetUrl(ctx context.Context, id string) (*ResetPasswordToken, error) {
	path := &url.URL{Path: "/api/v1/users/" + id + "/generate-reset-url"}
	resp, err := c.doJSON(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("reset password failed: %s", strings.TrimSpace(string(b)))
	}

	var data ResetPasswordToken
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &data, nil
}

func (c *ClientOIDC) PasswordSet(ctx context.Context, token *ResetPasswordToken, newPassword string) error {
	body := map[string]any{
		"password": newPassword,
	}
	path := &url.URL{Path: "/api/v1/auth/password/reset/" + token.ResetPasswordToken}
	resp, err := c.doJSON(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reset password 2nd factor failed: %s", strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *ClientOIDC) FindOrCreateUser(ctx context.Context, email, first, last, password string) (*User, error) {
	u, _ := c.FindUserByEmail(ctx, email)
	if u != nil {
		return u, nil
	}

	return c.CreateUser(ctx, email, first, last, password)
}

func (c *ClientOIDC) LoginUser(ctx context.Context, email, password string) (token string, setCookies []string, err error) {
	loginURL := c.BaseURL.ResolveReference(&url.URL{Path: "/api/v1/auth/user/signin"})
	body := map[string]string{
		"email":    email,
		"password": password,
	}

	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL.String(), strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("user login failed: %s", strings.TrimSpace(string(b)))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", nil, err
	}

	return authResp.Token, resp.Header.Values("Set-Cookie"), nil
}
