package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/notify"
)

// requestError is a failure the HTTP handler reports with its status code.
type requestError struct {
	status  int
	message string
}

// ipSwap is the outcome of one successful public IP replacement.
type ipSwap struct {
	OldIP, NewIP, AllocationID string
	Bandwidth                  int
}

func providerLabel(a app.Account) string {
	if a.SiteType == cloud.SiteAWS {
		return "AWS Lightsail"
	}
	return "阿里云"
}

func (s *Server) clientFor(a app.Account) cloud.Client {
	if s.CloudFactory != nil {
		return s.CloudFactory(a)
	}
	return s.Cloud
}

func (s *Server) replaceIP(w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["accountId"], 0))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "账号不存在")
		return
	}
	if a.CloudPresence == "missing" {
		s.error(w, 409, "云端实例不存在，无法更换公网 IP")
		return
	}
	client := s.clientFor(*a)
	if client == nil {
		s.cloudUnavailable(w)
		return
	}
	if a.InstanceStatus == "Releasing" {
		s.error(w, 409, "实例正在释放，无法更换公网 IP")
		return
	}
	// An empty allocation ID means an earlier attempt already released the old
	// EIP; the swap then resumes by binding a new one. A Lightsail instance on
	// a dynamic IP is swapped by attaching its first static IP.
	if a.PublicIPMode != "eip" && a.SiteType != cloud.SiteAWS {
		s.error(w, 400, "当前实例没有绑定 EIP，无法更换公网 IP")
		return
	}
	if _, busy := s.ipReplacing.LoadOrStore(id, true); busy {
		s.error(w, 409, "这台实例正在更换公网 IP，请稍候")
		return
	}
	if check := s.ipCheckSettings(); check.enabled() {
		// Swapping until an IP is reachable from mainland China can take several
		// minutes, far longer than one request may stay open.
		go func() {
			defer s.ipReplacing.Delete(id)
			s.replaceUntilReachable(id, check)
		}()
		s.json(w, 202, map[string]any{"success": true, "queued": true, "message": fmt.Sprintf("已开始更换公网 IP。换好后会从国内检测端口 %d，被墙会自动再换，最多 %d 次，结果见日志和通知。", check.Port, check.MaxSwaps)})
		return
	}
	defer s.ipReplacing.Delete(id)
	swap, failure := s.swapIP(client, a, true)
	if failure != nil {
		s.error(w, failure.status, failure.message)
		return
	}
	s.json(w, 200, map[string]any{"success": true, "message": "公网 IP 已更换", "data": map[string]any{"publicIp": swap.NewIP, "publicIpMode": "eip", "eipAllocationId": swap.AllocationID, "eipAddress": swap.NewIP, "eipManaged": true, "internetMaxBandwidthOut": swap.Bandwidth}})
}

// swapIP replaces the instance's public IP once. With announce it sends the
// usual notifications; the retry loop passes false and reports the final
// outcome itself.
func (s *Server) swapIP(client cloud.Client, a *app.Account, announce bool) (ipSwap, *requestError) {
	id := a.ID
	fail := func(status int, message string) (ipSwap, *requestError) {
		return ipSwap{}, &requestError{status: status, message: message}
	}
	var err error
	// Trust the cloud over the local row for what is bound right now: a
	// monitor pass that overlapped an earlier swap can leave a stale binding
	// here, and acting on it would strand the address that is really attached.
	if networkClient, ok := client.(cloud.InstancePublicNetworkClient); ok {
		if networks, networkErr := networkClient.DescribeInstancePublicNetworks(rctx(), a.RegionID, []string{a.InstanceID}); networkErr == nil {
			if network, attached := networks[a.InstanceID]; attached && network.AllocationID != "" {
				a.PublicIPMode, a.EIPAllocationID, a.EIPAddress = "eip", network.AllocationID, network.Address
				if network.Address != "" {
					a.PublicIP = network.Address
				}
			} else if a.SiteType == cloud.SiteAWS {
				a.EIPAllocationID, a.EIPAddress = "", ""
			}
		}
	}
	oldAllocationID, oldIP := a.EIPAllocationID, a.PublicIP
	// A Lightsail instance without a static IP still has a dynamic address,
	// which goes away when the first static IP is attached.
	dynamicIP := a.SiteType == cloud.SiteAWS && a.PublicIPMode != "eip"
	if dynamicIP {
		oldAllocationID = ""
	}
	template := cloud.EIPDetail{Bandwidth: a.InternetBandwidth}
	bound := oldAllocationID != ""
	detailClient, hasDetail := client.(cloud.EIPDetailClient)
	if hasDetail && oldAllocationID != "" {
		eip, err := detailClient.DescribeEIP(rctx(), a.RegionID, oldAllocationID)
		switch {
		case cloud.IsNotFound(err):
			oldAllocationID, bound = "", false
		case err != nil:
			return fail(400, "读取当前 EIP 失败: "+err.Error())
		default:
			if reason := eipReplaceBlocker(*eip, a.InstanceID); reason != "" {
				return fail(400, reason)
			}
			if eip.Address != "" {
				oldIP = eip.Address
			}
			if eip.Bandwidth < 1 {
				eip.Bandwidth = template.Bandwidth
			}
			template, bound = *eip, eip.InstanceID != ""
		}
	}
	bandwidth := template.Bandwidth

	// Release the old EIP before allocating the new one, as in the console:
	// the swap never holds two EIPs, so it cannot hit the EIP quota or leave
	// an extra one billing for idle time.
	if oldAllocationID != "" {
		s.settleIPTraffic(client, *a, oldIP)
		if bound {
			if err := client.UnassociateEIP(rctx(), a.RegionID, oldAllocationID); err != nil && !cloud.IsNotFound(err) {
				return fail(400, "旧 EIP 解绑失败: "+err.Error())
			}
		}
		if hasDetail {
			// Release is rejected until the asynchronous unbind finishes.
			if err := waitEIPAvailable(rctx(), detailClient, a.RegionID, oldAllocationID, eipUnbindTimeout); err != nil {
				s.Store.AddLog("warning", "等待旧 EIP 解绑超时: "+err.Error())
			}
		}
		if err := client.ReleaseEIP(rctx(), a.RegionID, oldAllocationID); err != nil && !cloud.IsNotFound(err) {
			message := "旧 EIP 释放失败: " + err.Error()
			if bound && client.AssociateEIP(rctx(), a.RegionID, oldAllocationID, a.InstanceID) == nil {
				message += "，已重新绑定旧 EIP"
			} else {
				message += "，旧 EIP 已解绑，请稍后再次更换"
			}
			s.Store.AddLog("error", message)
			return fail(400, message)
		}
		if err := s.Store.RetireInstanceTrafficIP(id, a.InstanceID, time.Now().Format("2006-01"), time.Now().UnixMilli()); err != nil {
			s.Store.AddLog("warning", "保存旧 IP 本月流量失败，新 IP 的流量可能从零开始: "+err.Error())
		}
		// From here the instance has no public IP. Record that so a failure
		// below leaves a state the next attempt resumes from.
		if err := s.Store.UpdateNetwork(id, map[string]any{"eip_allocation_id": "", "eip_address": "", "public_ip": "", "eip_managed": false}); err != nil {
			s.Store.AddLog("warning", "旧 EIP 已释放，但本地状态保存失败: "+err.Error())
		}
		// The old EIP went back to the provider's pool and may be handed to
		// someone else, so take it out of DNS.
		if _, err := s.Store.EnqueueDNSCleanup(oldIP, a.InstanceID, accountDisplay(*a), "ip_replaced"); err != nil {
			s.Store.AddLog("warning", "旧 IP 解析清理任务入队失败: "+err.Error())
		}
	}
	failWithoutIP := func(message string) (ipSwap, *requestError) {
		if dynamicIP {
			message += "。实例仍在使用原来的公网 IP，可再次点击更换 IP 重试"
		} else {
			message += "。实例当前没有公网 IP，可再次点击更换 IP 重试"
		}
		s.Store.AddLog("error", message)
		if announce {
			s.dispatchEvent(rctx(), notify.Event{Title: "公网 IP 更换失败", Summary: fmt.Sprintf("%s 公网 IP 更换失败", accountDisplay(*a)), AccountID: accountDisplay(*a), Text: fmt.Sprintf("【ECS 控制台】公网 IP 更换失败\n实例: %s\n旧 IP: %s\n区域: %s\n原因: %s", accountDisplay(*a), oldIP, a.RegionID, message), Fields: map[string]string{"old_ip": oldIP, "instance_id": a.InstanceID}})
		}
		return fail(400, message)
	}

	// The replacement is always pay-as-you-go and billed by traffic.
	var alloc, ip string
	if hasDetail {
		alloc, ip, err = detailClient.AllocateEIPLike(rctx(), a.RegionID, template)
		if err != nil {
			// The old line or resource group may be refused; fall back to defaults.
			s.Store.AddLog("warning", "按旧 EIP 线路申请新 EIP 失败，改用默认线路: "+err.Error())
		}
	}
	if !hasDetail || err != nil {
		alloc, ip, err = allocateEIP(rctx(), client, a.RegionID, bandwidth)
	}
	if err != nil {
		return failWithoutIP("新 EIP 申请失败: " + err.Error())
	}
	if err = client.AssociateEIP(rctx(), a.RegionID, alloc, a.InstanceID); err != nil {
		message := "新 EIP 绑定失败: " + err.Error()
		// An unbound EIP still bills for idle time; the next attempt allocates afresh.
		if releaseErr := client.ReleaseEIP(rctx(), a.RegionID, alloc); releaseErr != nil {
			message += fmt.Sprintf("；新 EIP %s 释放失败，请到%s控制台手动释放: %s", alloc, providerLabel(*a), releaseErr.Error())
		}
		return failWithoutIP(message)
	}
	// The controller created the new EIP, so instance release cleans it up.
	if err := s.Store.UpdateNetwork(id, map[string]any{"eip_allocation_id": alloc, "eip_address": ip, "public_ip": ip, "public_ip_mode": "eip", "eip_managed": true, "internet_max_bandwidth_out": bandwidth}); err != nil {
		return fail(500, "新 EIP 已绑定，但本地状态保存失败: "+err.Error())
	}
	if dynamicIP && oldIP != "" && oldIP != ip {
		// Attaching the static IP gave the dynamic address back to AWS.
		if _, err := s.Store.EnqueueDNSCleanup(oldIP, a.InstanceID, accountDisplay(*a), "ip_replaced"); err != nil {
			s.Store.AddLog("warning", "旧 IP 解析清理任务入队失败: "+err.Error())
		}
	}
	s.Store.AddLog("info", fmt.Sprintf("%s 公网 IP 已更换: %s -> %s", accountDisplay(*a), oldIP, ip))
	// The old address is gone already, so point DNS at the new one now even if
	// a later reachability check swaps again.
	s.syncDNSAfterSwap(id)
	if announce {
		text := fmt.Sprintf("【ECS 控制台】公网 IP 已更换\n实例: %s\n旧 IP: %s\n新 IP: %s\n区域: %s", accountDisplay(*a), oldIP, ip, a.RegionID)
		s.dispatchEvent(rctx(), notify.Event{Title: "公网 IP 已更换", Summary: fmt.Sprintf("%s 的公网 IP 已更换", accountDisplay(*a)), AccountID: accountDisplay(*a), Text: text, Fields: map[string]string{"old_ip": oldIP, "new_ip": ip, "instance_id": a.InstanceID}})
	}
	return ipSwap{OldIP: oldIP, NewIP: ip, AllocationID: alloc, Bandwidth: bandwidth}, nil
}

// syncDNSAfterSwap updates DNS in the background, so a slow DNS provider never
// holds up the swap or its HTTP response.
func (s *Server) syncDNSAfterSwap(accountID int64) {
	if s.SyncDNS == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		s.SyncDNS(ctx, accountID)
	}()
}

// replaceUntilReachable swaps the public IP, checks the new one from mainland
// China, and swaps again while it is blocked, up to cfg.MaxSwaps times. It
// stops as soon as an IP is reachable or the result cannot be determined, so
// an unreachable port or a broken probe never burns through IPs.
func (s *Server) replaceUntilReachable(id int64, cfg ipCheckSettings) {
	var (
		name, region, instanceID, firstIP, currentIP string
		blocked                                      []string
	)
	finish := func(kind, title, outcome string) {
		s.Store.AddLog(kind, fmt.Sprintf("%s %s", name, outcome))
		lines := []string{"【ECS 控制台】" + title, "实例: " + name, "区域: " + region}
		if firstIP != "" {
			lines = append(lines, "原 IP: "+firstIP)
		}
		if currentIP != "" {
			lines = append(lines, "当前 IP: "+currentIP)
		}
		if len(blocked) > 0 {
			lines = append(lines, "被墙的 IP: "+strings.Join(blocked, "、"))
		}
		lines = append(lines, "结果: "+outcome)
		s.dispatchEvent(rctx(), notify.Event{Title: title, Summary: name + " " + outcome, AccountID: name, Text: strings.Join(lines, "\n"), Fields: map[string]string{"old_ip": firstIP, "new_ip": currentIP, "instance_id": instanceID}})
	}
	for attempt := 1; attempt <= cfg.MaxSwaps; attempt++ {
		a, err := s.Store.Account(id, false)
		if err != nil {
			s.Store.AddLog("error", "更换公网 IP 中止：实例记录已不存在")
			return
		}
		name, region, instanceID = accountDisplay(*a), a.RegionID, a.InstanceID
		client := s.clientFor(*a)
		if client == nil {
			finish("error", "公网 IP 更换失败", "云客户端未配置，无法更换公网 IP")
			return
		}
		swap, failure := s.swapIP(client, a, false)
		if failure != nil {
			finish("error", "公网 IP 更换失败", fmt.Sprintf("第 %d 次更换失败: %s", attempt, failure.message))
			return
		}
		if firstIP == "" {
			firstIP = swap.OldIP
		}
		currentIP = swap.NewIP
		ctx, cancel := context.WithTimeout(context.Background(), ipCheckSettle+90*time.Second)
		result := s.checkIP(ctx, cfg, swap.NewIP, ipCheckSettle)
		cancel()
		s.saveIPCheck(id, swap.NewIP, result)
		switch result.Status {
		case ipCheckOK:
			finish("info", "公网 IP 已更换", fmt.Sprintf("公网 IP 已更换为 %s，国内可达（第 %d 次更换）", swap.NewIP, attempt))
			return
		case ipCheckUnknown:
			finish("warning", "公网 IP 已更换，未能确认是否被墙", fmt.Sprintf("公网 IP 已更换为 %s，但无法判断是否被墙: %s", swap.NewIP, result.Detail))
			return
		}
		blocked = append(blocked, swap.NewIP)
		if attempt < cfg.MaxSwaps {
			s.Store.AddLog("warning", fmt.Sprintf("%s 新 IP %s 在国内不可达（第 %d/%d 次），继续更换", name, swap.NewIP, attempt, cfg.MaxSwaps))
		}
	}
	finish("error", "公网 IP 更换后仍被墙", fmt.Sprintf("连续更换 %d 次，新 IP 在国内仍不可达，已停止自动更换", cfg.MaxSwaps))
}
