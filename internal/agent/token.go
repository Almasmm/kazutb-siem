package agent

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

type bearerTokenSource interface {
	Token(context.Context) (string, error)
}

type staticBearerToken string

func (s staticBearerToken) Token(context.Context) (string, error) { return string(s), nil }

type clientCredentialsTokenSource struct {
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string
	client       *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func newBearerTokenSource(config ForwarderConfig, client *http.Client) (bearerTokenSource, error) {
	staticToken := strings.TrimSpace(config.AccessToken)
	tokenURL := strings.TrimSpace(config.OAuthTokenURL)
	clientID := strings.TrimSpace(config.OAuthClientID)
	clientSecret := strings.TrimSpace(config.OAuthClientSecret)
	oauthConfigured := tokenURL != "" || clientID != "" || clientSecret != ""
	if staticToken != "" && oauthConfigured {
		return nil, errors.New("configure either static access token or OAuth client credentials, not both")
	}
	if staticToken != "" {
		return staticBearerToken(staticToken), nil
	}
	if tokenURL == "" || clientID == "" || clientSecret == "" {
		return nil, errors.New("collector authentication requires access token or complete OAuth client credentials")
	}
	parsed, err := url.Parse(tokenURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errors.New("valid OAuth token URL is required")
	}
	if parsed.User != nil {
		return nil, errors.New("credentials must not be embedded in OAuth token URL")
	}
	if parsed.Scheme != "https" && !config.AllowInsecureHTTP {
		return nil, errors.New("plain HTTP OAuth token endpoint is disabled")
	}
	return &clientCredentialsTokenSource{
		tokenURL: parsed.String(), clientID: clientID, clientSecret: clientSecret,
		scopes: append([]string(nil), config.OAuthScopes...), client: client,
	}, nil
}

func (s *clientCredentialsTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().UTC().Add(30*time.Second).Before(s.expiresAt) {
		return s.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope := strings.Join(s.scopes, " "); strings.TrimSpace(scope) != "" {
		form.Set("scope", scope)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create OAuth token request: %w", err)
	}
	request.SetBasicAuth(s.clientID, s.clientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("request OAuth token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return "", fmt.Errorf("OAuth token endpoint returned %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("decode OAuth token response: %w", err)
	}
	if strings.TrimSpace(tokenResponse.AccessToken) == "" || tokenResponse.ExpiresIn <= 0 ||
		(tokenResponse.TokenType != "" && !strings.EqualFold(tokenResponse.TokenType, "Bearer")) {
		return "", errors.New("OAuth token response is missing a valid bearer token or expiry")
	}
	s.token = strings.TrimSpace(tokenResponse.AccessToken)
	s.expiresAt = time.Now().UTC().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	return s.token, nil
}
