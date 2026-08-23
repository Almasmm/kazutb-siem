package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

type CredentialManagerConfig struct {
	ServerURL       string
	TenantID        string
	EnrollmentToken string
	StateDirectory  string
	CredentialFile  string
	IdentityFile    string
	AgentID         string
	AgentName       string
	AgentVersion    string
	CAFile          string
	CertificateFile string
	PrivateKeyFile  string
	AllowInsecure   bool
	Timeout         time.Duration
}

type storedAgentIdentity struct {
	AgentID   string    `json:"agent_id"`
	CreatedAt time.Time `json:"created_at"`
}

type storedAgentCredential struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	CollectorID string    `json:"collector_id"`
}

type CredentialManager struct {
	client          *http.Client
	transport       *http.Transport
	enrollEndpoint  string
	rotateEndpoint  string
	tenantID        string
	enrollmentToken string
	stateDirectory  string
	credentialFile  string
	identityFile    string
	configuredID    string
	agentName       string
	agentVersion    string
	current         storedAgentCredential
}

func OpenCredentialManager(config CredentialManagerConfig) (*CredentialManager, error) {
	config.ServerURL = strings.TrimSpace(config.ServerURL)
	config.TenantID = strings.TrimSpace(config.TenantID)
	config.StateDirectory = strings.TrimSpace(config.StateDirectory)
	if config.ServerURL == "" || config.TenantID == "" || config.StateDirectory == "" {
		return nil, errors.New("agent server URL, tenant ID and state directory are required")
	}
	serverURL, err := url.Parse(config.ServerURL)
	if err != nil || serverURL.Host == "" || (serverURL.Scheme != "https" && serverURL.Scheme != "http") || serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return nil, errors.New("agent server URL must be an absolute HTTP(S) URL without query or fragment")
	}
	if serverURL.Scheme != "https" && !config.AllowInsecure {
		return nil, errors.New("agent enrollment requires HTTPS unless insecure HTTP is explicitly enabled")
	}
	if err := os.MkdirAll(config.StateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create agent state directory: %w", err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(config.CAFile) != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		body, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read agent enrollment CA: %w", err)
		}
		if !roots.AppendCertsFromPEM(body) {
			return nil, errors.New("agent enrollment CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if (strings.TrimSpace(config.CertificateFile) == "") != (strings.TrimSpace(config.PrivateKeyFile) == "") {
		return nil, errors.New("agent enrollment client certificate and private key must be configured together")
	}
	if strings.TrimSpace(config.CertificateFile) != "" {
		certificate, err := tls.LoadX509KeyPair(config.CertificateFile, config.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load agent enrollment client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	credentialFile := strings.TrimSpace(config.CredentialFile)
	if credentialFile == "" {
		credentialFile = filepath.Join(config.StateDirectory, "credential.json")
	}
	identityFile := strings.TrimSpace(config.IdentityFile)
	if identityFile == "" {
		identityFile = filepath.Join(config.StateDirectory, "identity.json")
	}
	baseURL := strings.TrimRight(serverURL.String(), "/")
	return &CredentialManager{
		client: &http.Client{Transport: transport, Timeout: config.Timeout}, transport: transport,
		enrollEndpoint: baseURL + "/api/v1/agent-enrollment", rotateEndpoint: baseURL + "/api/v1/agent-credentials/rotate",
		tenantID: config.TenantID, enrollmentToken: strings.TrimSpace(config.EnrollmentToken), stateDirectory: config.StateDirectory,
		credentialFile: credentialFile, identityFile: identityFile, configuredID: strings.TrimSpace(config.AgentID),
		agentName: strings.TrimSpace(config.AgentName), agentVersion: strings.TrimSpace(config.AgentVersion),
	}, nil
}

func (m *CredentialManager) Close() {
	m.transport.CloseIdleConnections()
}

func (m *CredentialManager) Ensure(ctx context.Context) (core.AgentCredentialGrant, error) {
	credential, err := m.loadCredential()
	if err == nil {
		if !credential.ExpiresAt.After(time.Now().UTC()) {
			return core.AgentCredentialGrant{}, errors.New("stored agent credential has expired; issue a new enrollment token")
		}
		m.current = credential
		return credentialGrant(credential), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return core.AgentCredentialGrant{}, err
	}
	if m.enrollmentToken == "" {
		return core.AgentCredentialGrant{}, errors.New("agent has no credential; KCSP_AGENT_ENROLLMENT_TOKEN is required for first enrollment")
	}
	identity, err := m.loadOrCreateIdentity()
	if err != nil {
		return core.AgentCredentialGrant{}, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return core.AgentCredentialGrant{}, fmt.Errorf("resolve agent hostname: %w", err)
	}
	name := m.agentName
	if name == "" {
		name = hostname
	}
	request := core.AgentEnrollmentRequest{
		EnrollmentToken: m.enrollmentToken, AgentID: identity.AgentID, Name: name, Hostname: hostname,
		Version: m.agentVersion, Platform: runtime.GOOS, Architecture: runtime.GOARCH,
	}
	var response core.AgentEnrollmentResponse
	if err := m.postJSON(ctx, m.enrollEndpoint, "", request, &response, http.StatusCreated); err != nil {
		return core.AgentCredentialGrant{}, err
	}
	credential = storedAgentCredential{
		AccessToken: strings.TrimSpace(response.Credential.AccessToken), TokenType: response.Credential.TokenType,
		ExpiresAt: response.Credential.ExpiresAt.UTC(), CollectorID: response.Collector.ID,
	}
	if !validStoredCredential(credential) || response.Collector.ID != identity.AgentID {
		return core.AgentCredentialGrant{}, errors.New("agent enrollment response contains an invalid credential or collector identity")
	}
	if err := writePrivateJSON(m.credentialFile, credential); err != nil {
		return core.AgentCredentialGrant{}, fmt.Errorf("persist enrolled agent credential: %w", err)
	}
	m.current = credential
	m.enrollmentToken = ""
	return credentialGrant(credential), nil
}

func (m *CredentialManager) ShouldRotate(now time.Time, before time.Duration) bool {
	if m.current.AccessToken == "" {
		return false
	}
	if before <= 0 {
		before = 24 * time.Hour
	}
	return !m.current.ExpiresAt.After(now.UTC().Add(before))
}

func (m *CredentialManager) Rotate(ctx context.Context) (core.AgentCredentialGrant, error) {
	if m.current.AccessToken == "" {
		credential, err := m.loadCredential()
		if err != nil {
			return core.AgentCredentialGrant{}, err
		}
		m.current = credential
	}
	var grant core.AgentCredentialGrant
	if err := m.postJSON(ctx, m.rotateEndpoint, m.current.AccessToken, map[string]interface{}{}, &grant, http.StatusOK); err != nil {
		return core.AgentCredentialGrant{}, err
	}
	replacement := storedAgentCredential{
		AccessToken: strings.TrimSpace(grant.AccessToken), TokenType: grant.TokenType,
		ExpiresAt: grant.ExpiresAt.UTC(), CollectorID: m.current.CollectorID,
	}
	if !validStoredCredential(replacement) {
		return core.AgentCredentialGrant{}, errors.New("agent credential rotation response is invalid")
	}
	if err := writePrivateJSON(m.credentialFile, replacement); err != nil {
		return core.AgentCredentialGrant{}, fmt.Errorf("persist rotated agent credential: %w", err)
	}
	m.current = replacement
	return credentialGrant(replacement), nil
}

func (m *CredentialManager) loadOrCreateIdentity() (storedAgentIdentity, error) {
	body, err := readPrivateFile(m.identityFile, 16<<10)
	if err == nil {
		var identity storedAgentIdentity
		if json.Unmarshal(body, &identity) != nil || strings.TrimSpace(identity.AgentID) == "" {
			return storedAgentIdentity{}, errors.New("stored agent identity is invalid")
		}
		if m.configuredID != "" && identity.AgentID != m.configuredID {
			return storedAgentIdentity{}, errors.New("configured agent ID does not match persisted identity")
		}
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return storedAgentIdentity{}, err
	}
	agentID := m.configuredID
	if agentID == "" {
		agentID = core.NewID("agt")
	}
	identity := storedAgentIdentity{AgentID: agentID, CreatedAt: time.Now().UTC()}
	if err := writePrivateJSON(m.identityFile, identity); err != nil {
		return storedAgentIdentity{}, fmt.Errorf("persist agent identity: %w", err)
	}
	return identity, nil
}

func (m *CredentialManager) loadCredential() (storedAgentCredential, error) {
	body, err := readPrivateFile(m.credentialFile, 64<<10)
	if err != nil {
		return storedAgentCredential{}, err
	}
	var credential storedAgentCredential
	if err := json.Unmarshal(body, &credential); err != nil || !validStoredCredential(credential) {
		return storedAgentCredential{}, errors.New("stored agent credential is invalid")
	}
	return credential, nil
}

func (m *CredentialManager) postJSON(ctx context.Context, endpoint, accessToken string, input, output interface{}, expectedStatus int) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode agent control request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create agent control request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
		request.Header.Set("X-KCSP-Tenant-ID", m.tenantID)
	}
	response, err := m.client.Do(request)
	if err != nil {
		return fmt.Errorf("send agent control request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 128<<10))
	if err != nil {
		return fmt.Errorf("read agent control response: %w", err)
	}
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("agent control endpoint returned %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	if err := json.Unmarshal(responseBody, output); err != nil {
		return fmt.Errorf("decode agent control response: %w", err)
	}
	return nil
}

func credentialGrant(credential storedAgentCredential) core.AgentCredentialGrant {
	return core.AgentCredentialGrant{AccessToken: credential.AccessToken, TokenType: credential.TokenType, ExpiresAt: credential.ExpiresAt}
}

func validStoredCredential(credential storedAgentCredential) bool {
	return strings.HasPrefix(credential.AccessToken, "kcsp_agent_") && credential.TokenType == "Bearer" &&
		credential.CollectorID != "" && credential.ExpiresAt.After(time.Now().UTC())
}

func readPrivateFile(path string, maximumBytes int64) ([]byte, error) {
	if maximumBytes <= 0 {
		return nil, errors.New("agent private state maximum size must be positive")
	}
	selected := path
	// #nosec G304 -- selected is a local administrator credential path; a single handle prevents Stat/Open races.
	file, err := os.Open(selected)
	if errors.Is(err, os.ErrNotExist) {
		selected = path + ".previous"
		// #nosec G304 -- the fallback is the fixed previous-version suffix of the same administrator path.
		file, err = os.Open(selected)
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximumBytes {
		return nil, errors.New("agent private state file is invalid or oversized")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("agent private state file has group or world permissions")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximumBytes {
		return nil, errors.New("agent private state file is oversized")
	}
	return body, nil
}

func writePrivateJSON(path string, value interface{}) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".kcsp-private-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		backup := path + ".previous"
		_ = os.Remove(backup)
		movedExisting := false
		if err := os.Rename(path, backup); err == nil {
			movedExisting = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(temporaryName, path); err != nil {
			if movedExisting {
				_ = os.Rename(backup, path)
			}
			return err
		}
		_ = os.Remove(backup)
	} else if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	// #nosec G304 -- directory is the local administrator-configured private credential directory created above.
	if directoryHandle, err := os.Open(directory); err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}
