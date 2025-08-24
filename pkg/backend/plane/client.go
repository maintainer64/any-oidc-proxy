package plane

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

type csrfResp struct {
	CSRFToken string `json:"csrf_token"`
}

func (pb *PlaneBackend) loginUser(ctx context.Context, email, password string) ([]string, error) {
	// CookieJar, чтобы автоматически сохранять и отправлять куки (csrftoken, session и т.д.)
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client := &http.Client{
		Jar:     jar,
		Timeout: pb.httpClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Disable automatic redirects
		},
	}

	// 1) GET /auth/get-csrf-token/
	reqCSRF, _ := http.NewRequestWithContext(ctx, "GET", pb.baseURL+"/auth/get-csrf-token/", nil)

	respCSRF, err := client.Do(reqCSRF)
	if err != nil {
		return []string{}, fmt.Errorf("get csrf: %w", err)
	}
	defer respCSRF.Body.Close()

	if respCSRF.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(respCSRF.Body)
		return []string{}, fmt.Errorf("get csrf: status %d: %s", respCSRF.StatusCode, string(b))
	}

	var cr csrfResp
	if err := json.NewDecoder(respCSRF.Body).Decode(&cr); err != nil {
		return []string{}, fmt.Errorf("decode csrf json: %w", err)
	}
	if cr.CSRFToken == "" {
		return []string{}, fmt.Errorf("empty csrf_token")
	}

	// 2) POST /auth/sign-in/
	form := url.Values{}
	form.Set("csrfmiddlewaretoken", cr.CSRFToken)
	form.Set("email", email)
	form.Set("password", password)

	reqSign, _ := http.NewRequestWithContext(ctx, "POST", pb.baseURL+"/auth/sign-in/", strings.NewReader(form.Encode()))
	reqSign.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqSign.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")

	respSign, err := client.Do(reqSign)
	if err != nil {
		return []string{}, fmt.Errorf("sign-in request: %w", err)
	}
	defer respSign.Body.Close()

	if respSign.StatusCode != http.StatusOK && respSign.StatusCode != http.StatusFound && respSign.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(respSign.Body)
		return []string{}, fmt.Errorf("sign-in: status %d: %s", respSign.StatusCode, string(b))
	}
	if err != nil {
		return []string{}, fmt.Errorf("read response body: %w", err)
	}
	return respSign.Header.Values("Set-Cookie"), nil
}
