package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/dns"
)

// ipWatchTick is how often the scheduled check looks at whether a round is due.
var ipWatchTick = time.Minute

// RunIPWatch checks every running instance from mainland China on the
// configured interval and swaps the public IP of any that are blocked.
func (s *Server) RunIPWatch(ctx context.Context) {
	ticker := time.NewTicker(ipWatchTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			cfg := s.ipCheckSettings()
			if !cfg.enabled() || cfg.Interval <= 0 {
				continue
			}
			last, _ := strconv.ParseInt(s.Store.GetSetting("ipcheck_auto_last", "0"), 10, 64)
			if now.Unix()-last < int64(cfg.Interval)*60 {
				continue
			}
			_ = s.Store.SetSetting("ipcheck_auto_last", strconv.FormatInt(now.Unix(), 10))
			s.ipWatchRound(ctx, cfg, now)
		}
	}
}

// ipWatchCandidate reports whether the scheduled check should look at a and
// could swap its IP if it is blocked.
func (s *Server) ipWatchCandidate(a app.Account, now time.Time) bool {
	if a.InstanceID == "" || a.IsDeleted != 0 || a.CloudPresence == "missing" || a.InstanceStatus != "Running" {
		return false
	}
	if !dns.IsPublicIPv4(a.PublicIP) || s.Store.InstanceExpiry(a.InstanceID).Expired(now) {
		return false
	}
	return a.PublicIPMode == "eip" || a.SiteType == cloud.SiteAWS
}

func (s *Server) ipWatchRound(ctx context.Context, cfg ipCheckSettings, now time.Time) {
	accounts, err := s.Store.LoadAccounts(false)
	if err != nil {
		return
	}
	var blocked []app.Account
	checked := 0
	for _, a := range accounts {
		if ctx.Err() != nil {
			return
		}
		if !s.ipWatchCandidate(a, now) {
			continue
		}
		if _, busy := s.ipReplacing.Load(a.ID); busy {
			continue
		}
		checkCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		result := s.checkIP(checkCtx, cfg, a.PublicIP, ipCheckManualSettle)
		cancel()
		if ctx.Err() != nil {
			return
		}
		s.saveIPCheck(a.ID, a.PublicIP, result)
		switch result.Status {
		case ipCheckOK:
			checked++
		case ipCheckBlocked:
			checked++
			blocked = append(blocked, a)
		}
	}
	if len(blocked) == 0 {
		return
	}
	names := make([]string, 0, len(blocked))
	for _, a := range blocked {
		names = append(names, fmt.Sprintf("%s(%s)", accountDisplay(a), a.PublicIP))
	}
	// Most machines going dark at once points at the probe's own network,
	// not at the IPs; swapping them all would only burn addresses.
	if len(blocked) >= 2 && len(blocked)*2 > checked {
		s.Store.AddLog("warning", fmt.Sprintf("定时被墙检测：%d/%d 台同时在国内不可达，疑似探测机网络问题，本轮不自动更换 IP：%s", len(blocked), checked, strings.Join(names, "、")))
		return
	}
	for _, a := range blocked {
		if ctx.Err() != nil {
			return
		}
		if _, busy := s.ipReplacing.LoadOrStore(a.ID, true); busy {
			continue
		}
		s.Store.AddLog("warning", fmt.Sprintf("定时被墙检测：%s 的 %s 在国内不可达，开始自动更换公网 IP", accountDisplay(a), a.PublicIP))
		s.replaceUntilReachable(a.ID, cfg)
		s.ipReplacing.Delete(a.ID)
	}
}
