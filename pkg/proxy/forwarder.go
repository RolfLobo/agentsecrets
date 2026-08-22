package proxy

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultTimeout for outbound HTTP requests.
const DefaultTimeout = 30 * time.Second

// ForwardResult holds the raw response from the upstream API.
type ForwardResult struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
}

// MaxResponseBodySize bounds the maximum memory buffered from an upstream response (50MB).
const MaxResponseBodySize = 50 * 1024 * 1024

// Forward sends the outbound request and returns the result.
// The caller is responsible for building the request (URL, method, headers, body).
// This function reads and closes the upstream response body.
func Forward(client *http.Client, req *http.Request) (*ForwardResult, error) {
	// Ensure Host header matches the target URL
	req.Host = req.URL.Host

	start := time.Now()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach upstream: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read upstream response: %w", err)
	}

	return &ForwardResult{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Duration:   time.Since(start),
	}, nil
}
