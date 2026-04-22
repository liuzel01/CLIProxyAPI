package management

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "net/http"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
)

type TokenPolicy struct {
    ID                 string   `json:"id"`
    Token              string   `json:"token"`
    Owner              string   `json:"owner"`
    Purpose            string   `json:"purpose,omitempty"`
    AllowedModels      []string `json:"allowed_models,omitempty"`
    AllowedScopes      []string `json:"allowed_scopes,omitempty"`
    DailyRequestLimit  int64    `json:"daily_request_limit,omitempty"`
    MonthlyRequestLimit int64   `json:"monthly_request_limit,omitempty"`
    DailyTokenLimit    int64    `json:"daily_token_limit,omitempty"`
    MonthlyTokenLimit  int64    `json:"monthly_token_limit,omitempty"`
    ExpiresAt          string   `json:"expires_at,omitempty"`
    Status             string   `json:"status"` // active|disabled|revoked
    CreatedAt          string   `json:"created_at"`
    UpdatedAt          string   `json:"updated_at"`
    RotatedFrom        string   `json:"rotated_from,omitempty"`
}

type tokenPolicyFile struct {
    Version int           `json:"version"`
    Tokens  []TokenPolicy `json:"tokens"`
}

func (h *Handler) tokenPolicyFilePath() string {
    authDir := "./auths"
    if h != nil && h.cfg != nil && strings.TrimSpace(h.cfg.AuthDir) != "" {
        authDir = strings.TrimSpace(h.cfg.AuthDir)
    }
    return filepath.Join(authDir, "token-policies.json")
}

func (h *Handler) loadTokenPolicies() (tokenPolicyFile, error) {
    path := h.tokenPolicyFilePath()
    _ = os.MkdirAll(filepath.Dir(path), 0o700)
    raw, err := os.ReadFile(path)
    if err != nil {
        if os.IsNotExist(err) {
            return tokenPolicyFile{Version: 1, Tokens: []TokenPolicy{}}, nil
        }
        return tokenPolicyFile{}, err
    }
    var f tokenPolicyFile
    if err := json.Unmarshal(raw, &f); err != nil {
        return tokenPolicyFile{}, err
    }
    if f.Version == 0 {
        f.Version = 1
    }
    if f.Tokens == nil {
        f.Tokens = []TokenPolicy{}
    }
    return f, nil
}

func (h *Handler) saveTokenPolicies(f tokenPolicyFile) error {
    path := h.tokenPolicyFilePath()
    _ = os.MkdirAll(filepath.Dir(path), 0o700)
    if f.Version == 0 {
        f.Version = 1
    }
    data, err := json.MarshalIndent(f, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0o600)
}

func normalizeSlice(in []string) []string {
    if len(in) == 0 {
        return nil
    }
    out := make([]string, 0, len(in))
    seen := map[string]struct{}{}
    for _, v := range in {
        t := strings.TrimSpace(v)
        if t == "" {
            continue
        }
        if _, ok := seen[t]; ok {
            continue
        }
        seen[t] = struct{}{}
        out = append(out, t)
    }
    sort.Strings(out)
    return out
}

func newID() string {
    b := make([]byte, 8)
    if _, err := rand.Read(b); err != nil {
        return time.Now().UTC().Format("20060102150405")
    }
    return hex.EncodeToString(b)
}

// GET /v0/management/tokens
func (h *Handler) GetTokenPolicies(c *gin.Context) {
    h.mu.Lock()
    defer h.mu.Unlock()

    f, err := h.loadTokenPolicies()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed", "message": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"tokens": f.Tokens})
}

// POST /v0/management/tokens
func (h *Handler) CreateTokenPolicy(c *gin.Context) {
    var req struct {
        Token               string   `json:"token"`
        Owner               string   `json:"owner"`
        Purpose             string   `json:"purpose"`
        AllowedModels       []string `json:"allowed_models"`
        AllowedScopes       []string `json:"allowed_scopes"`
        DailyRequestLimit   int64    `json:"daily_request_limit"`
        MonthlyRequestLimit int64    `json:"monthly_request_limit"`
        DailyTokenLimit     int64    `json:"daily_token_limit"`
        MonthlyTokenLimit   int64    `json:"monthly_token_limit"`
        ExpiresAt           string   `json:"expires_at"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
        return
    }
    token := strings.TrimSpace(req.Token)
    owner := strings.TrimSpace(req.Owner)
    if token == "" || owner == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "token and owner are required"})
        return
    }

    h.mu.Lock()
    defer h.mu.Unlock()

    f, err := h.loadTokenPolicies()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed", "message": err.Error()})
        return
    }
    for _, t := range f.Tokens {
        if t.Token == token {
            c.JSON(http.StatusConflict, gin.H{"error": "token already exists"})
            return
        }
    }

    now := time.Now().UTC().Format(time.RFC3339)
    item := TokenPolicy{
        ID:                 newID(),
        Token:              token,
        Owner:              owner,
        Purpose:            strings.TrimSpace(req.Purpose),
        AllowedModels:      normalizeSlice(req.AllowedModels),
        AllowedScopes:      normalizeSlice(req.AllowedScopes),
        DailyRequestLimit:  req.DailyRequestLimit,
        MonthlyRequestLimit: req.MonthlyRequestLimit,
        DailyTokenLimit:    req.DailyTokenLimit,
        MonthlyTokenLimit:  req.MonthlyTokenLimit,
        ExpiresAt:          strings.TrimSpace(req.ExpiresAt),
        Status:             "active",
        CreatedAt:          now,
        UpdatedAt:          now,
    }
    f.Tokens = append(f.Tokens, item)
    if err := h.saveTokenPolicies(f); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"ok": true, "token": item})
}

// PATCH /v0/management/tokens/:id
func (h *Handler) PatchTokenPolicy(c *gin.Context) {
    id := strings.TrimSpace(c.Param("id"))
    if id == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "id required"})
        return
    }

    var req struct {
        Owner               *string   `json:"owner"`
        Purpose             *string   `json:"purpose"`
        AllowedModels       *[]string `json:"allowed_models"`
        AllowedScopes       *[]string `json:"allowed_scopes"`
        DailyRequestLimit   *int64    `json:"daily_request_limit"`
        MonthlyRequestLimit *int64    `json:"monthly_request_limit"`
        DailyTokenLimit     *int64    `json:"daily_token_limit"`
        MonthlyTokenLimit   *int64    `json:"monthly_token_limit"`
        ExpiresAt           *string   `json:"expires_at"`
        Status              *string   `json:"status"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
        return
    }

    h.mu.Lock()
    defer h.mu.Unlock()

    f, err := h.loadTokenPolicies()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed", "message": err.Error()})
        return
    }

    idx := -1
    for i := range f.Tokens {
        if f.Tokens[i].ID == id {
            idx = i
            break
        }
    }
    if idx < 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
        return
    }

    item := f.Tokens[idx]
    if req.Owner != nil { item.Owner = strings.TrimSpace(*req.Owner) }
    if req.Purpose != nil { item.Purpose = strings.TrimSpace(*req.Purpose) }
    if req.AllowedModels != nil { item.AllowedModels = normalizeSlice(*req.AllowedModels) }
    if req.AllowedScopes != nil { item.AllowedScopes = normalizeSlice(*req.AllowedScopes) }
    if req.DailyRequestLimit != nil { item.DailyRequestLimit = *req.DailyRequestLimit }
    if req.MonthlyRequestLimit != nil { item.MonthlyRequestLimit = *req.MonthlyRequestLimit }
    if req.DailyTokenLimit != nil { item.DailyTokenLimit = *req.DailyTokenLimit }
    if req.MonthlyTokenLimit != nil { item.MonthlyTokenLimit = *req.MonthlyTokenLimit }
    if req.ExpiresAt != nil { item.ExpiresAt = strings.TrimSpace(*req.ExpiresAt) }
    if req.Status != nil {
        s := strings.ToLower(strings.TrimSpace(*req.Status))
        if s != "active" && s != "disabled" && s != "revoked" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
            return
        }
        item.Status = s
    }
    item.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
    f.Tokens[idx] = item

    if err := h.saveTokenPolicies(f); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"ok": true, "token": item})
}

// POST /v0/management/tokens/:id/rotate
func (h *Handler) RotateTokenPolicy(c *gin.Context) {
    id := strings.TrimSpace(c.Param("id"))
    if id == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "id required"})
        return
    }
    var req struct { NewToken string `json:"new_token"` }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
        return
    }
    newToken := strings.TrimSpace(req.NewToken)
    if newToken == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "new_token required"})
        return
    }

    h.mu.Lock()
    defer h.mu.Unlock()

    f, err := h.loadTokenPolicies()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed", "message": err.Error()})
        return
    }

    for _, t := range f.Tokens {
        if t.Token == newToken {
            c.JSON(http.StatusConflict, gin.H{"error": "new token already exists"})
            return
        }
    }

    idx := -1
    for i := range f.Tokens {
        if f.Tokens[i].ID == id {
            idx = i
            break
        }
    }
    if idx < 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
        return
    }

    old := f.Tokens[idx]
    old.Status = "disabled"
    old.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
    f.Tokens[idx] = old

    now := time.Now().UTC().Format(time.RFC3339)
    next := old
    next.ID = newID()
    next.Token = newToken
    next.Status = "active"
    next.RotatedFrom = old.ID
    next.CreatedAt = now
    next.UpdatedAt = now
    f.Tokens = append(f.Tokens, next)

    if err := h.saveTokenPolicies(f); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"ok": true, "old": old, "new": next})
}
