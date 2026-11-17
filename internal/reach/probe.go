package reach

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	headerTime      = "X-Probe-Time"
	headerSignature = "X-Probe-Signature"
	// maxSkew bounds how old a signed request may be, which also limits how
	// long a captured request can be replayed.
	maxSkew = 5 * time.Minute
	// MinTokenLength keeps the shared secret long enough to resist guessing.
	MinTokenLength = 16
)

// Handler serves the probe API: GET /health and POST /check, both signed.
func Handler(token string) http.Handler {
	limiter := &rateLimiter{limit: 60, window: time.Minute}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if _, ok := authorize(w, r, token); !ok {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().Unix()})
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		body, ok := authorize(w, r, token)
		if !ok {
			return
		}
		if !limiter.allow(time.Now()) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "检测过于频繁，请稍后再试"})
			return
		}
		var req CheckRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式无效"})
			return
		}
		if err := req.Normalize(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, Dial(r.Context(), req))
	})
	return mux
}

func authorize(w http.ResponseWriter, r *http.Request, token string) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求读取失败"})
		return nil, false
	}
	stamp := r.Header.Get(headerTime)
	seconds, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "缺少签名"})
		return nil, false
	}
	now := time.Now()
	if skew := now.Sub(time.Unix(seconds, 0)); skew > maxSkew || skew < -maxSkew {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": fmt.Sprintf("请求时间和探测机时间相差过大（探测机时间 %s），请校准两台机器的时钟", now.UTC().Format(time.RFC3339))})
		return nil, false
	}
	expected := Sign(token, r.Method, r.URL.Path, stamp, body)
	if !hmac.Equal([]byte(expected), []byte(strings.ToLower(r.Header.Get(headerSignature)))) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "签名不正确，请检查密钥是否一致"})
		return nil, false
	}
	return body, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	start  time.Time
	count  int
}

func (l *rateLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.start) >= l.window {
		l.start, l.count = now, 0
	}
	l.count++
	return l.count <= l.limit
}

// Client calls a probe from the panel.
type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
}

func (c Client) do(ctx context.Context, method, path string, body []byte, output any) error {
	base := strings.TrimRight(strings.TrimSpace(c.URL), "/")
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set(headerTime, stamp)
	req.Header.Set(headerSignature, Sign(c.Token, method, req.URL.Path, stamp, body))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var problem struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &problem) == nil && problem.Error != "" {
			return errors.New(problem.Error)
		}
		return fmt.Errorf("探测机返回 HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(raw, output); err != nil {
		return errors.New("探测机返回的内容无法解析，请确认地址指向的是探测程序")
	}
	return nil
}

// Health confirms the probe is up and the token matches.
func (c Client) Health(ctx context.Context) error {
	var response struct {
		OK bool `json:"ok"`
	}
	if err := c.do(ctx, http.MethodGet, "/health", nil, &response); err != nil {
		return err
	}
	if !response.OK {
		return errors.New("探测机没有返回正常状态")
	}
	return nil
}

// Check asks the probe to connect to the target from where it runs.
func (c Client) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CheckResponse{}, err
	}
	var response CheckResponse
	err = c.do(ctx, http.MethodPost, "/check", body, &response)
	return response, err
}
