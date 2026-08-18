package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// isWebSocketUpgrade определяет запрос на апгрейд до WebSocket.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// handleWebSocketTunnel проксирует WebSocket-соединение в бэкенд «сырым»
// туннелем (http.Client не умеет апгрейдить соединения сам).
func (a *App) handleWebSocketTunnel(w http.ResponseWriter, r *http.Request, proxyURL *url.URL) {
	target := *proxyURL
	target.Path = singleJoiningSlash(target.Path, r.URL.Path)
	if r.URL.RawQuery != "" {
		target.RawQuery = r.URL.RawQuery
	}

	upstream := target.Host
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	upConn, err := dialer.DialContext(context.Background(), "tcp", upstream)
	if err != nil {
		log.Infof("ws tunnel dial %s: %v", upstream, err)
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer upConn.Close()

	// Строим запрос к апстриму, сохраняя заголовки клиента
	req := r.Clone(r.Context())
	req.URL = &target
	req.RequestURI = ""
	req.Host = target.Host
	req.Header.Set("Host", target.Host)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", r.Host)
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		req.Header.Set("X-Forwarded-For", ip)
	}
	if len(req.Header.Get("Origin")) == 0 && r.TLS != nil {
		req.Header.Set("Origin", "https://"+r.Host)
	}

	if err := req.Write(upConn); err != nil {
		log.Infof("ws tunnel write: %v", err)
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}

	br := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		log.Infof("ws tunnel read response: %v", err)
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Errorf("ws tunnel: hijacking not supported")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Infof("ws tunnel hijack: %v", err)
		return
	}
	defer clientConn.Close()

	// Отдаём клиенту ответ апстрима дословно (101 Switching Protocols)
	err = resp.Write(clientBuf)
	if err != nil {
		log.Infof("ws tunnel write response: %v", err)
		return
	}
	if err := clientBuf.Flush(); err != nil {
		return
	}

	// Двусторонняя проброска байтов
	errc := make(chan struct{}, 2)
	go func() {
		io.Copy(upConn, clientBuf)
		errc <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, br)
		errc <- struct{}{}
	}()
	<-errc
	<-errc
	close(errc)
}

// singleJoiningSlash склеивает пути без дублирования слэшей
// (аналог одноимённой функции из net/http/httputil).
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
