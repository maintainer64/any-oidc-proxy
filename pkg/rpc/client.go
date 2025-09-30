package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"time"
)

type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int         `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      int         `json:"id"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type RPCClient struct {
	baseURL    string
	headers    map[string]string
	timeout    time.Duration
	transport  http.RoundTripper
	httpClient *http.Client
}

type Option func(*RPCClient)

func NewRPCClient(baseURL string, options ...Option) *RPCClient {
	client := &RPCClient{
		baseURL: baseURL,
		headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
		timeout: 30 * time.Second,
	}

	for _, option := range options {
		option(client)
	}

	// Инициализируем HTTP клиент
	client.httpClient = &http.Client{
		Timeout:   client.timeout,
		Transport: client.transport,
	}

	return client
}

func WithHeader(key, value string) Option {
	return func(c *RPCClient) {
		c.headers[key] = value
	}
}

func WithHeaders(headers map[string]string) Option {
	return func(c *RPCClient) {
		for key, value := range headers {
			c.headers[key] = value
		}
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(c *RPCClient) {
		c.timeout = timeout
	}
}

func WithTransport(transport http.RoundTripper) Option {
	return func(c *RPCClient) {
		c.transport = transport
	}
}

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *RPCClient) {
		c.httpClient = httpClient
	}
}

func (c *RPCClient) Call(ctx context.Context, method string, params interface{}, result interface{}) error {
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	log.Debugf("JSON-RPC request: %s, url: %s", string(body), c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Устанавливаем все заголовки
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var rpcResponse JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResponse); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if rpcResponse.Error != nil {
		return fmt.Errorf("RPC error %d: %s", rpcResponse.Error.Code, rpcResponse.Error.Message)
	}

	// Преобразуем результат в нужный тип
	resultBytes, err := json.Marshal(rpcResponse.Result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	if err := json.Unmarshal(resultBytes, result); err != nil {
		return fmt.Errorf("unmarshal result: %w", err)
	}

	return nil
}
