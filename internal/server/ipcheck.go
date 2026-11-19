package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/reach"
	"github.com/Kori1c/ecs-controller/internal/store"
)

const (
	ipCheckOK      = "ok"
	ipCheckBlocked = "blocked"
	ipCheckUnknown = "unknown"

	ipCheckDefaultPort     = 22
	ipCheckDefaultMaxSwaps = 5
	ipCheckSwapLimit       = 10
	// ipCheckDefaultInterval is how often, in minutes, running instances are
	// checked from mainland China; 0 turns the scheduled check off.
	ipCheckDefaultInterval = 20
	ipCheckIntervalLimit   = 1440
)

var (
	// ipCheckSettle is how long a freshly attached IP gets to start routing
	// before the panel gives up reaching it.
	ipCheckSettle = 45 * time.Second
	// ipCheckManualSettle is the same wait for an IP that is already in use.
	ipCheckManualSettle = 6 * time.Second
	// ipCheckConfirmDelay separates the two probe runs that must both fail
	// before an IP is declared blocked.
	ipCheckConfirmDelay = 5 * time.Second
	ipCheckRetryPause   = 2 * time.Second
	// localDial is the panel's own connection test; tests replace it.
	localDial = reach.Dial
)

// ipCheckSettings configures the mainland-China reachability check. The probe
// is a gfw-probe process on a machine inside mainland China.
type ipCheckSettings struct {
	ProbeURL string
	Token    string
	Port     int
	MaxSwaps int
	// Interval is the scheduled check's period in minutes; 0 is off.
	Interval int
	HTTP     *http.Client
}

func (c ipCheckSettings) enabled() bool { return c.ProbeURL != "" && c.Token != "" }

func (c ipCheckSettings) probe() reach.Client {
	return reach.Client{URL: c.ProbeURL, Token: c.Token, HTTP: c.HTTP}
}

func (s *Server) ipCheckSettings() ipCheckSettings {
	token, _ := s.Store.OpenSecret(s.Store.GetSetting("ipcheck_probe_token", ""))
	return ipCheckSettings{
		ProbeURL: strings.TrimSpace(s.Store.GetSetting("ipcheck_probe_url", "")),
		Token:    token,
		Port:     clampInt(s.Store.GetSetting("ipcheck_port", ""), ipCheckDefaultPort, 1, 65535),
		MaxSwaps: clampInt(s.Store.GetSetting("ipcheck_max_swaps", ""), ipCheckDefaultMaxSwaps, 1, ipCheckSwapLimit),
		Interval: clampInt(s.Store.GetSetting("ipcheck_auto_interval", ""), ipCheckDefaultInterval, 0, ipCheckIntervalLimit),
	}
}

func clampInt(raw string, fallback, low, high int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < low || value > high {
		return fallback
	}
	return value
}

func (s *Server) ipCheckConfig() map[string]any {
	cfg := s.ipCheckSettings()
	return map[string]any{"probe_url": cfg.ProbeURL, "probe_token": masked(s.Store.GetSetting("ipcheck_probe_token", "")), "port": cfg.Port, "max_swaps": cfg.MaxSwaps, "auto_interval": cfg.Interval}
}

func validProbeURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("探测机地址无效，需要形如 http://国内机器IP:8433 的地址")
	}
	return nil
}

func (s *Server) saveIPCheckConfig(data map[string]any) error {
	probeURL := strings.TrimRight(strings.TrimSpace(stringValue(data["probe_url"])), "/")
	if probeURL != "" {
		if err := validProbeURL(probeURL); err != nil {
			return err
		}
	}
	token := stringValue(data["probe_token"])
	if token != "" && token != "********" && len(token) < reach.MinTokenLength {
		return fmt.Errorf("探测密钥至少需要 %d 位", reach.MinTokenLength)
	}
	port := int(number(data["port"], ipCheckDefaultPort))
	if port < 1 || port > 65535 {
		return fmt.Errorf("检测端口必须在 1 到 65535 之间")
	}
	maxSwaps := int(number(data["max_swaps"], ipCheckDefaultMaxSwaps))
	if maxSwaps < 1 || maxSwaps > ipCheckSwapLimit {
		return fmt.Errorf("最多更换次数必须在 1 到 %d 之间", ipCheckSwapLimit)
	}
	interval := int(number(data["auto_interval"], ipCheckDefaultInterval))
	if interval < 0 || interval > ipCheckIntervalLimit {
		return fmt.Errorf("定时检测间隔必须在 0 到 %d 分钟之间", ipCheckIntervalLimit)
	}
	for key, value := range map[string]string{"ipcheck_probe_url": probeURL, "ipcheck_port": strconv.Itoa(port), "ipcheck_max_swaps": strconv.Itoa(maxSwaps), "ipcheck_auto_interval": strconv.Itoa(interval)} {
		if err := s.Store.SetSetting(key, value); err != nil {
			return err
		}
	}
	return s.saveSecret("ipcheck_probe_token", token)
}

type ipCheckResult struct {
	Status  string
	Detail  string
	Refused bool
}

// checkIP decides whether ip is blocked from mainland China on the configured
// port. The probe's answer alone cannot tell a blocked IP from a closed port,
// so the panel connects from where it runs as well: reachable from the panel
// but not from the probe means blocked; unreachable from both means unknown.
func (s *Server) checkIP(ctx context.Context, cfg ipCheckSettings, ip string, settle time.Duration) ipCheckResult {
	target := fmt.Sprintf("%s:%d", ip, cfg.Port)
	request := reach.CheckRequest{IP: ip, Port: cfg.Port, Attempts: 3, TimeoutMS: 3000}

	// A new IP needs a moment before it routes; asking the probe sooner would
	// report a healthy IP as blocked.
	local := reach.CheckResponse{}
	deadline := time.Now().Add(settle)
	for {
		local = localDial(ctx, reach.CheckRequest{IP: ip, Port: cfg.Port, Attempts: 1, TimeoutMS: 3000})
		if local.Reachable || !time.Now().Before(deadline) || !pause(ctx, ipCheckRetryPause) {
			break
		}
	}

	remote, err := cfg.probe().Check(ctx, request)
	if err != nil {
		return ipCheckResult{Status: ipCheckUnknown, Detail: "国内探测机不可用: " + err.Error()}
	}
	reachable := func(response reach.CheckResponse) ipCheckResult {
		detail := fmt.Sprintf("国内可以连上 %s，耗时 %d ms", target, response.LatencyMS)
		if response.Refused {
			detail = fmt.Sprintf("国内能到达 %s，TCP 连接被拒绝", target)
		}
		return ipCheckResult{Status: ipCheckOK, Detail: detail, Refused: response.Refused}
	}
	if remote.Reachable {
		return reachable(remote)
	}
	if !local.Reachable {
		return ipCheckResult{Status: ipCheckUnknown, Detail: fmt.Sprintf("面板和国内探测机都连不上 %s，请确认实例已开机并且防火墙放行了这个端口", target)}
	}
	// One failed run can be a network blip; only two in a row count.
	if pause(ctx, ipCheckConfirmDelay) {
		if remote, err = cfg.probe().Check(ctx, request); err == nil && remote.Reachable {
			return reachable(remote)
		}
	}
	return ipCheckResult{Status: ipCheckBlocked, Detail: fmt.Sprintf("面板可以连上 %s，但国内探测机连不上", target)}
}

func pause(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (s *Server) saveIPCheck(accountID int64, ip string, result ipCheckResult) {
	if err := s.Store.SaveIPCheck(store.IPCheck{AccountID: accountID, IP: ip, Status: result.Status, Detail: result.Detail}); err != nil {
		s.Store.AddLog("warning", "保存被墙检测结果失败: "+err.Error())
	}
}

// checkInstanceIP runs the reachability check on an instance's current IP.
func (s *Server) checkInstanceIP(requestCtx context.Context, w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["accountId"], 0))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "账号不存在")
		return
	}
	cfg := s.ipCheckSettings()
	if !cfg.enabled() {
		s.error(w, 400, "请先在「系统设置 → 被墙检测」里填写国内探测机地址和密钥")
		return
	}
	if a.PublicIP == "" {
		s.error(w, 400, "这台实例当前没有公网 IP")
		return
	}
	if _, busy := s.ipReplacing.Load(id); busy {
		s.error(w, 409, "这台实例正在更换公网 IP，请稍候")
		return
	}
	ctx, cancel := context.WithTimeout(requestCtx, 50*time.Second)
	defer cancel()
	result := s.checkIP(ctx, cfg, a.PublicIP, ipCheckManualSettle)
	if requestCtx.Err() != nil {
		return
	}
	s.saveIPCheck(id, a.PublicIP, result)
	s.json(w, 200, map[string]any{"success": true, "message": result.Detail, "data": map[string]any{"ip": a.PublicIP, "port": cfg.Port, "refused": result.Refused, "status": result.Status, "detail": result.Detail, "checkedAt": time.Now().Unix()}})
}

// testIPProbe checks the probe address and token being edited, before saving.
func (s *Server) testIPProbe(w http.ResponseWriter, data map[string]any) {
	probeURL := strings.TrimRight(strings.TrimSpace(stringValue(data["probe_url"])), "/")
	if probeURL == "" {
		s.error(w, 400, "请填写探测机地址")
		return
	}
	if err := validProbeURL(probeURL); err != nil {
		s.error(w, 400, err.Error())
		return
	}
	token := stringValue(data["probe_token"])
	if token == "" || token == "********" {
		token = s.ipCheckSettings().Token
	}
	if token == "" {
		s.error(w, 400, "请填写探测密钥")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := (reach.Client{URL: probeURL, Token: token}).Health(ctx); err != nil {
		s.error(w, 400, "探测机连接失败: "+err.Error())
		return
	}
	s.json(w, 200, map[string]any{"success": true, "message": "探测机连接正常，密钥正确"})
}
