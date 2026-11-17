package reach

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDialReportsOpenAndRefusedPortsAsReachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if got := dial(context.Background(), address, 1, time.Second); !got.Reachable || got.Refused {
		t.Fatalf("open port=%+v", got)
	}
	listener.Close()
	if got := dial(context.Background(), address, 1, time.Second); !got.Reachable || !got.Refused {
		t.Fatalf("closed port=%+v", got)
	}
}

func TestDialTimesOutOnSilentHost(t *testing.T) {
	// 192.0.2.0/24 is reserved for documentation and never answers.
	if got := dial(context.Background(), "192.0.2.1:9", 1, 200*time.Millisecond); got.Reachable || got.Error == "" {
		t.Fatalf("silent host=%+v", got)
	}
}

func TestNormalizeRejectsNonPublicTargets(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.8", "192.168.1.1", "172.16.5.4", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "not-an-ip"} {
		req := CheckRequest{IP: ip, Port: 22}
		if err := req.Normalize(); err == nil {
			t.Errorf("%s should be rejected", ip)
		}
	}
	req := CheckRequest{IP: "8.8.8.8", Port: 443, Attempts: 99, TimeoutMS: 999999}
	if err := req.Normalize(); err != nil || req.Attempts != maxAttempts || req.TimeoutMS != int(maxTimeout/time.Millisecond) {
		t.Fatalf("normalized=%+v err=%v", req, err)
	}
	if err := (&CheckRequest{IP: "8.8.8.8", Port: 70000}).Normalize(); err == nil {
		t.Fatal("port out of range should be rejected")
	}
}

func TestProbeRequiresValidSignature(t *testing.T) {
	const token = "0123456789abcdef-token"
	server := httptest.NewServer(Handler(token))
	defer server.Close()

	if err := (Client{URL: server.URL + "/", Token: token}).Health(context.Background()); err != nil {
		t.Fatalf("health with the right token: %v", err)
	}
	err := (Client{URL: server.URL, Token: "another-token-0123456789"}).Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "签名不正确") {
		t.Fatalf("wrong token error=%v", err)
	}

	stale := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/health", nil)
	req.Header.Set(headerTime, stale)
	req.Header.Set(headerSignature, Sign(token, http.MethodGet, "/health", stale, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale request status=%d", resp.StatusCode)
	}

	resp, err = http.Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned request status=%d", resp.StatusCode)
	}
}

func TestProbeRefusesPrivateTargets(t *testing.T) {
	const token = "0123456789abcdef-token"
	server := httptest.NewServer(Handler(token))
	defer server.Close()
	_, err := (Client{URL: server.URL, Token: token}).Check(context.Background(), CheckRequest{IP: "127.0.0.1", Port: 22})
	if err == nil || !strings.Contains(err.Error(), "公网 IP") {
		t.Fatalf("private target error=%v", err)
	}
}
