// Package reach checks whether a public IP answers TCP connections. The panel
// uses it directly for its own view of an IP, and the probe that runs on a
// machine inside mainland China serves the same check over HTTP.
package reach

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

// CheckRequest asks for TCP connection attempts to IP:Port.
type CheckRequest struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Attempts  int    `json:"attempts"`
	TimeoutMS int    `json:"timeout_ms"`
}

// CheckResponse is the outcome of a CheckRequest.
type CheckResponse struct {
	// Reachable is true when any attempt got an answer from the host.
	Reachable bool `json:"reachable"`
	// Refused is true when the answer was a refused connection: the IP is
	// routable but nothing listens on the port.
	Refused   bool   `json:"refused"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

const (
	maxAttempts = 5
	maxTimeout  = 10 * time.Second
)

// Normalize validates the request and fills in defaults.
func (r *CheckRequest) Normalize() error {
	ip := net.ParseIP(r.IP)
	if ip == nil || !PublicIP(ip) {
		return errors.New("只能检测公网 IP")
	}
	if r.Port < 1 || r.Port > 65535 {
		return errors.New("端口必须在 1 到 65535 之间")
	}
	if r.Attempts < 1 {
		r.Attempts = 3
	}
	if r.Attempts > maxAttempts {
		r.Attempts = maxAttempts
	}
	timeout := time.Duration(r.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	r.TimeoutMS = int(timeout / time.Millisecond)
	return nil
}

// PublicIP reports whether ip is a routable public address, so the probe
// cannot be used to scan the network it sits in.
func PublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 carrier-grade NAT and 0.0.0.0/8.
		if v4[0] == 0 || (v4[0] == 100 && v4[1]&0xc0 == 64) {
			return false
		}
	}
	return true
}

// Dial runs the request from this machine. A refused connection counts as
// reachable: the reset came from the host, so the IP itself is not blocked.
func Dial(ctx context.Context, req CheckRequest) CheckResponse {
	if err := req.Normalize(); err != nil {
		return CheckResponse{Error: err.Error()}
	}
	return dial(ctx, net.JoinHostPort(req.IP, strconv.Itoa(req.Port)), req.Attempts, time.Duration(req.TimeoutMS)*time.Millisecond)
}

func dial(ctx context.Context, address string, attempts int, timeout time.Duration) CheckResponse {
	response := CheckResponse{}
	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			response.Error = ctx.Err().Error()
			break
		}
		started := time.Now()
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
		elapsed := time.Since(started).Milliseconds()
		if err == nil {
			_ = conn.Close()
			return CheckResponse{Reachable: true, LatencyMS: elapsed}
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return CheckResponse{Reachable: true, Refused: true, LatencyMS: elapsed}
		}
		response.Error = err.Error()
	}
	return response
}

// Sign authenticates a probe request without sending the token itself, which
// would otherwise cross the border in clear text on a plain HTTP probe URL.
func Sign(token, method, path, unixTime string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(method + "\n" + path + "\n" + unixTime + "\n"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
