package metabase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ClientOIDC struct {
	BaseURL       *url.URL
	AdminEmail    string
	AdminPassword string
	HTTP          *http.Client

	AdminSession    string
	AdminSessionMu  *sync.Mutex
	AdminSessionExp time.Time
}

type User struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	IsActive  bool   `json:"is_active"`
}

type UserData struct {
	Data []User `json:"data"`
}

func (m *ClientOIDC) ensureAdmin(ctx context.Context) error {
	m.AdminSessionMu.Lock()
	defer m.AdminSessionMu.Unlock()

	// If session valid, try keep
	if m.AdminSession != "" && time.Now().Before(m.AdminSessionExp) {
		return nil
	}
	// login
	loginURL := m.BaseURL.ResolveReference(&url.URL{Path: "/api/session"})
	body := map[string]string{
		"username": m.AdminEmail,
		"password": m.AdminPassword,
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL.String(), strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin login failed: %s", strings.TrimSpace(string(b)))
	}
	var sr struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return err
	}
	if sr.ID == "" {
		return errors.New("empty admin session id")
	}
	m.AdminSession = sr.ID
	// Metabase sessions default lifetime is long; set soft TTL
	m.AdminSessionExp = time.Now().Add(8 * time.Hour)
	return nil
}

func (m *ClientOIDC) doJSON(
	ctx context.Context,
	method string,
	urlPath *url.URL,
	in any,
) (*http.Response, error) {
	if err := m.ensureAdmin(ctx); err != nil {
		return nil, err
	}
	u := m.BaseURL.ResolveReference(urlPath)
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = strings.NewReader(string(b))
	}
	req, _ := http.NewRequestWithContext(ctx, method, u.String(), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Metabase-Session", m.AdminSession)
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	// Handle expired session (401)
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		// reset and retry once
		m.AdminSessionMu.Lock()
		m.AdminSession = ""
		m.AdminSessionExp = time.Time{}
		m.AdminSessionMu.Unlock()
		if err := m.ensureAdmin(ctx); err != nil {
			return nil, err
		}
		req, _ = http.NewRequestWithContext(ctx, method, u.String(), body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Metabase-Session", m.AdminSession)
		return m.HTTP.Do(req)
	}
	return resp, nil
}

func (m *ClientOIDC) ListUsers(ctx context.Context) (*UserData, error) {
	resp, err := m.doJSON(
		ctx,
		http.MethodGet,
		&url.URL{Path: "/api/user", RawQuery: "status=all"},
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
	var data UserData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (m *ClientOIDC) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	users, err := m.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	if users == nil {
		return nil, errors.New("no users found")
	}
	for _, u := range users.Data {
		if strings.EqualFold(strings.TrimSpace(u.Email), strings.TrimSpace(email)) {
			u := u
			return &u, nil
		}
	}
	return nil, nil
}

func (m *ClientOIDC) CreateUser(ctx context.Context, email, first, last, password string) (*User, error) {
	body := map[string]any{
		"email":      email,
		"first_name": first,
		"last_name":  last,
		"password":   password,
		"is_active":  true,
	}
	resp, err := m.doJSON(ctx, http.MethodPost, &url.URL{Path: "/api/user"}, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create user failed: %s", strings.TrimSpace(string(b)))
	}
	var u User
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (m *ClientOIDC) UpdateUser(ctx context.Context, id int, patch map[string]any) error {
	path := &url.URL{Path: "/api/user/" + strconv.Itoa(id)}
	resp, err := m.doJSON(ctx, http.MethodPut, path, patch)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update user failed: %s", strings.TrimSpace(string(b)))
	}
	return nil
}

func (m *ClientOIDC) ReactivateUser(ctx context.Context, id int) error {
	path := &url.URL{Path: "/api/user/" + strconv.Itoa(id) + "/reactivate"}
	resp, err := m.doJSON(ctx, http.MethodPut, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reactivate user failed: %s", strings.TrimSpace(string(b)))
	}
	return nil
}

func (m *ClientOIDC) ResetPassword(ctx context.Context, id int, newPassword string) error {
	// Preferred endpoint
	path := &url.URL{Path: "/api/user/" + strconv.Itoa(id) + "/password"}
	body := map[string]any{
		"password": newPassword,
	}
	resp, err := m.doJSON(ctx, http.MethodPut, path, body)
	if err == nil && (resp.StatusCode == 200 || resp.StatusCode == 204) {
		resp.Body.Close()
		return nil
	}
	if resp != nil {
		resp.Body.Close()
	}
	return nil
}

func (m *ClientOIDC) FindOrCreateUser(ctx context.Context, email, first, last, password string) (*User, error) {
	u, err := m.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if u != nil {
		return u, nil
	}
	return m.CreateUser(ctx, email, first, last, password)
}

func (m *ClientOIDC) LoginUser(ctx context.Context, email, password string) (sessionID string, setCookies []string, err error) {
	loginURL := m.BaseURL.ResolveReference(&url.URL{Path: "/api/session"})
	body := map[string]string{
		"username": email,
		"password": password,
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, loginURL.String(), strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("user login failed: %s", strings.TrimSpace(string(b)))
	}
	var sr struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return "", nil, err
	}
	return sr.ID, resp.Header.Values("Set-Cookie"), nil
}
