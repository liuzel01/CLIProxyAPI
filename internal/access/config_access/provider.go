package configaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

// Register ensures the config-access provider is available to the access manager.
func Register(cfg *sdkconfig.SDKConfig) {
	if cfg == nil {
		sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
		return
	}

	keys := normalizeKeys(cfg.APIKeys)
	if len(keys) == 0 {
		sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
		return
	}

	sdkaccess.RegisterProvider(
		sdkaccess.AccessProviderTypeConfigAPIKey,
		newProvider(sdkaccess.DefaultAccessProviderName, keys),
	)
}

type provider struct {
	name string
	keys map[string]struct{}
}

func newProvider(name string, keys []string) *provider {
	providerName := strings.TrimSpace(name)
	if providerName == "" {
		providerName = sdkaccess.DefaultAccessProviderName
	}
	keySet := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		keySet[key] = struct{}{}
	}
	return &provider{name: providerName, keys: keySet}
}

func (p *provider) Identifier() string {
	if p == nil || p.name == "" {
		return sdkaccess.DefaultAccessProviderName
	}
	return p.name
}

func (p *provider) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if p == nil {
		return nil, sdkaccess.NewNotHandledError()
	}
	if len(p.keys) == 0 {
		return nil, sdkaccess.NewNotHandledError()
	}
	authHeader := r.Header.Get("Authorization")
	authHeaderGoogle := r.Header.Get("X-Goog-Api-Key")
	authHeaderAnthropic := r.Header.Get("X-Api-Key")
	queryKey := ""
	queryAuthToken := ""
	if r.URL != nil {
		queryKey = r.URL.Query().Get("key")
		queryAuthToken = r.URL.Query().Get("auth_token")
	}
	if authHeader == "" && authHeaderGoogle == "" && authHeaderAnthropic == "" && queryKey == "" && queryAuthToken == "" {
		return nil, sdkaccess.NewNoCredentialsError()
	}

	apiKey := extractBearerToken(authHeader)

	candidates := []struct {
		value  string
		source string
	}{
		{apiKey, "authorization"},
		{authHeaderGoogle, "x-goog-api-key"},
		{authHeaderAnthropic, "x-api-key"},
		{queryKey, "query-key"},
		{queryAuthToken, "query-auth-token"},
	}

	for _, candidate := range candidates {
		if candidate.value == "" {
			continue
		}
		if _, ok := p.keys[candidate.value]; !ok {
			continue
		}

		policyMeta, policyErr := validateTokenPolicy(r, candidate.value)
		if policyErr != nil {
			return nil, policyErr
		}

		metadata := map[string]string{"source": candidate.source}
		for k, v := range policyMeta {
			metadata[k] = v
		}

		return &sdkaccess.Result{
			Provider:  p.Identifier(),
			Principal: candidate.value,
			Metadata:  metadata,
		}, nil
	}

	return nil, sdkaccess.NewInvalidCredentialError()
}

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return header
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return header
	}
	return strings.TrimSpace(parts[1])
}

func normalizeKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if _, exists := seen[trimmedKey]; exists {
			continue
		}
		seen[trimmedKey] = struct{}{}
		normalized = append(normalized, trimmedKey)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

type tokenPolicy struct {
	ID            string   `json:"id"`
	Token         string   `json:"token"`
	Owner         string   `json:"owner"`
	Purpose       string   `json:"purpose,omitempty"`
	AllowedModels []string `json:"allowed_models,omitempty"`
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
	Status        string   `json:"status"`
}

type tokenPolicyFile struct {
	Version int           `json:"version"`
	Tokens  []tokenPolicy `json:"tokens"`
}

var policyCache struct {
	sync.RWMutex
	path    string
	modTime time.Time
	data    tokenPolicyFile
}

func validateTokenPolicy(r *http.Request, key string) (map[string]string, *sdkaccess.AuthError) {
	policies, loaded, err := loadPolicyFile()
	if err != nil {
		return nil, sdkaccess.NewInvalidCredentialError()
	}
	if !loaded {
		// Compatibility mode: no policy file means no policy enforcement yet.
		return nil, nil
	}

	var matched *tokenPolicy
	for i := range policies.Tokens {
		if policies.Tokens[i].Token == key {
			matched = &policies.Tokens[i]
			break
		}
	}
	if matched == nil {
		// Compatibility mode: unmanaged keys continue to work.
		return nil, nil
	}

	status := strings.ToLower(strings.TrimSpace(matched.Status))
	if status == "" {
		status = "active"
	}
	if status != "active" {
		return nil, sdkaccess.NewInvalidCredentialError()
	}

	if strings.TrimSpace(matched.ExpiresAt) != "" {
		expiresAt, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(matched.ExpiresAt))
		if parseErr != nil || time.Now().After(expiresAt) {
			return nil, sdkaccess.NewInvalidCredentialError()
		}
	}

	if len(matched.AllowedScopes) > 0 && !scopeAllowed(matched.AllowedScopes, r) {
		return nil, sdkaccess.NewInvalidCredentialError()
	}

	if len(matched.AllowedModels) > 0 {
		model, modelErr := extractRequestModel(r)
		if modelErr != nil {
			return nil, sdkaccess.NewInvalidCredentialError()
		}
		if strings.TrimSpace(model) == "" || !inStringSliceCI(matched.AllowedModels, model) {
			return nil, sdkaccess.NewInvalidCredentialError()
		}
	}

	meta := map[string]string{"tokenPolicyManaged": "true"}
	if strings.TrimSpace(matched.ID) != "" {
		meta["tokenPolicyId"] = strings.TrimSpace(matched.ID)
	}
	if strings.TrimSpace(matched.Owner) != "" {
		meta["tokenOwner"] = strings.TrimSpace(matched.Owner)
	}
	if strings.TrimSpace(matched.Purpose) != "" {
		meta["tokenPurpose"] = strings.TrimSpace(matched.Purpose)
	}
	return meta, nil
}

func scopeAllowed(scopes []string, r *http.Request) bool {
	path := "/"
	method := ""
	if r != nil {
		if r.URL != nil && strings.TrimSpace(r.URL.Path) != "" {
			path = r.URL.Path
		}
		method = strings.ToUpper(strings.TrimSpace(r.Method))
	}
	for _, raw := range scopes {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if s == "*" {
			return true
		}
		if strings.EqualFold(s, "management") && strings.HasPrefix(path, "/v0/management") {
			return true
		}
		if strings.HasSuffix(s, "*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if strings.Contains(s, " ") {
			parts := strings.SplitN(s, " ", 2)
			sm := strings.ToUpper(strings.TrimSpace(parts[0]))
			sp := strings.TrimSpace(parts[1])
			if sm == method && sp != "" && strings.HasPrefix(path, sp) {
				return true
			}
			continue
		}
		if strings.HasPrefix(path, s) {
			return true
		}
	}
	return false
}

func extractRequestModel(r *http.Request) (string, error) {
	if r == nil {
		return "", nil
	}
	if r.URL != nil {
		if queryModel := strings.TrimSpace(r.URL.Query().Get("model")); queryModel != "" {
			return queryModel, nil
		}
	}
	if r.Body == nil {
		return "", nil
	}
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	if len(bytes.TrimSpace(buf)) == 0 {
		return "", nil
	}
	var payload map[string]any
	if err := json.Unmarshal(buf, &payload); err != nil {
		return "", nil
	}
	if raw, ok := payload["model"]; ok {
		if model, ok := raw.(string); ok {
			return strings.TrimSpace(model), nil
		}
	}
	return "", nil
}

func inStringSliceCI(items []string, target string) bool {
	t := strings.TrimSpace(target)
	if t == "" {
		return false
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), t) {
			return true
		}
	}
	return false
}

func loadPolicyFile() (tokenPolicyFile, bool, error) {
	path := policyPath()
	if strings.TrimSpace(path) == "" {
		return tokenPolicyFile{}, false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return tokenPolicyFile{}, false, nil
		}
		return tokenPolicyFile{}, false, err
	}

	policyCache.RLock()
	if policyCache.path == path && !info.ModTime().After(policyCache.modTime) {
		cached := policyCache.data
		policyCache.RUnlock()
		return cached, true, nil
	}
	policyCache.RUnlock()

	raw, err := os.ReadFile(path)
	if err != nil {
		return tokenPolicyFile{}, false, err
	}
	var parsed tokenPolicyFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return tokenPolicyFile{}, false, err
	}

	policyCache.Lock()
	policyCache.path = path
	policyCache.modTime = info.ModTime()
	policyCache.data = parsed
	policyCache.Unlock()

	return parsed, true, nil
}

func policyPath() string {
	if p := strings.TrimSpace(os.Getenv("CLI_PROXY_TOKEN_POLICY_PATH")); p != "" {
		return p
	}
	baseDirCandidates := []string{}
	if p := strings.TrimSpace(os.Getenv("CLI_PROXY_AUTH_PATH")); p != "" {
		baseDirCandidates = append(baseDirCandidates, p)
	}
	baseDirCandidates = append(baseDirCandidates, "/root/.cli-proxy-api", "./auths")
	for _, base := range baseDirCandidates {
		if strings.TrimSpace(base) == "" {
			continue
		}
		p := filepath.Join(base, "token-policies.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// fallback write target (may not exist yet)
	return filepath.Join("/root/.cli-proxy-api", "token-policies.json")
}
