package docmost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// setup выполняет initial setup Docmost: создаёт воркспейс и первого
// (владеющего) пользователя. Возвращает Set-Cookie хедеры ответа.
func (d *DocmostBackend) setup(ctx context.Context, email, name, password string) ([]string, error) {
	body := map[string]string{
		"name":          name,
		"email":         email,
		"password":      password,
		"workspaceName": d.workspaceName,
	}
	if d.hostname != "" {
		body["hostname"] = d.hostname
	}
	return d.postLogin(ctx, "/api/auth/setup", body)
}

// login выполняет вход через /api/auth/login и возвращает Set-Cookie хедеры.
func (d *DocmostBackend) login(ctx context.Context, email, password string) ([]string, error) {
	body := map[string]string{
		"email":    email,
		"password": password,
	}
	return d.postLogin(ctx, "/api/auth/login", body)
}

func (d *DocmostBackend) postLogin(ctx context.Context, path string, body map[string]string) ([]string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s failed with status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return nil, fmt.Errorf("%s returned no session cookies", path)
	}
	return cookies, nil
}
