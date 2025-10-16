package oauth

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// HTTPClient defines the interface for making HTTP requests.
// This abstraction allows for testing and custom implementations.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// defaultHTTPClient is a production HTTP client with sensible defaults.
type defaultHTTPClient struct {
	client *http.Client
}

// newDefaultHTTPClient creates an HTTP client optimized for OAuth operations.
func newDefaultHTTPClient(timeout time.Duration, tlsConfig *tls.Config, insecureSkipVerify bool) HTTPClient {
	// Create custom TLS config
	customTLS := tlsConfig
	if customTLS == nil {
		customTLS = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	} else {
		// Clone to avoid modifying the original
		customTLS = tlsConfig.Clone()
	}

	if insecureSkipVerify {
		customTLS.InsecureSkipVerify = true
	}

	// Create transport with optimized settings
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       customTLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: timeout,
	}

	return &defaultHTTPClient{
		client: &http.Client{
			Timeout:   timeout,
			Transport: &retryTransport{base: transport},
		},
	}
}

// Do executes the HTTP request.
func (c *defaultHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// retryTransport wraps an http.RoundTripper with retry logic for transient failures.
type retryTransport struct {
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper with retry logic.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	const maxRetries = 3
	const initialBackoff = 100 * time.Millisecond

	var lastErr error
	backoff := initialBackoff

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := t.base.RoundTrip(req)

		// Success - return immediately
		if err == nil && !shouldRetry(resp) {
			return resp, nil
		}

		// Don't retry client errors (4xx) except 429 Too Many Requests
		if err == nil && resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			return resp, nil
		}

		// Save error and cleanup response
		lastErr = err
		if resp != nil {
			resp.Body.Close()
		}

		// Last attempt - return error
		if attempt == maxRetries-1 {
			break
		}

		// Wait before retry with exponential backoff
		time.Sleep(backoff)
		backoff *= 2
	}

	if lastErr != nil {
		return nil, lastErr
	}

	// This shouldn't happen, but return a generic error if it does
	return nil, http.ErrHandlerTimeout
}

// shouldRetry determines if an HTTP response indicates a transient failure.
func shouldRetry(resp *http.Response) bool {
	if resp == nil {
		return true
	}

	// Retry on server errors (5xx) and rate limiting (429)
	return resp.StatusCode == 429 || resp.StatusCode >= 500
}
