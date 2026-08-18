package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// discoveryStub поднимает минимальный OIDC discovery-сервер, чтобы
// newApp() мог создать OIDCAuthenticator без внешних зависимостей.
func discoveryStub(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/jwks")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testApp(t *testing.T, proxyURL string) *App {
	t.Helper()
	disc := discoveryStub(t)
	cfg := &Config{
		ListenAddr:                 "127.0.0.1:0",
		ExternalURL:                "https://docs.gubanov.site",
		Type:                       "zabbix",
		ZabbixToken:                "test-token",
		ProxyURL:                   proxyURL,
		OIDCIssuer:                 disc.URL,
		OIDCClientID:               "test-client",
		OIDCClientSecret:           "test-secret",
		OIDCPath:                   "/openid/",
		StateSecret:                "test-state-secret",
		SecureCookies:              false,
		SessionCookieNames:         []string{"authToken"},
		ProxyRewriteLocationHeader: false,
		LogLevel:                   "info",
	}
	app, err := newApp(cfg)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	return app
}

// TestWebSocketTunnel проверяет, что запросы с Upgrade: websocket
// проксируются сырым туннелем: 101 от апстрима доходит до клиента,
// данные идут в обе стороны.
func TestWebSocketTunnel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			t.Errorf("upstream: ожидался websocket-upgrade, заголовки: %v", r.Header)
		}
		if r.URL.Path != "/ws/chat" || r.URL.RawQuery != "x=1" {
			t.Errorf("upstream path/query = %q?%q, want /ws/chat?x=1", r.URL.Path, r.URL.RawQuery)
		}
		if got := r.Header.Get("X-Forwarded-Host"); got != "docs.gubanov.site" {
			t.Errorf("X-Forwarded-Host = %q", got)
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("upstream: hijacking not supported")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("upstream hijack: %v", err)
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: abc123\r\n\r\n")
		buf.Flush()
		// echo
		io.Copy(conn, buf)
	}))
	defer upstream.Close()

	app := testApp(t, upstream.URL)
	proxySrv := httptest.NewServer(app.routes())
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET /ws/chat?x=1 HTTP/1.1\r\nHost: docs.gubanov.site\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Errorf("Upgrade header = %q", resp.Header.Get("Upgrade"))
	}

	// echo: клиент -> туннель -> апстрим -> обратно
	msg := []byte("hello-via-tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

// TestProxyPassesHTTPRequests — обычные запросы идут через reverse proxy
// без туннеля (проверка, что WS-ветка не сломала HTTP).
func TestProxyPassesHTTPRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			t.Error("upstream: обычный запрос не должен быть websocket")
		}
		w.Header().Set("X-Upstream", "yes")
		io.WriteString(w, "pong")
	}))
	defer upstream.Close()

	app := testApp(t, upstream.URL)
	proxySrv := httptest.NewServer(app.routes())
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/some/page?q=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" || resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("resp = %q / %q", body, resp.Header.Get("X-Upstream"))
	}
}
