package server

import (
	"fmt"
	"math"
	"net/http"
)

// setInstanceTrafficLimit stores one machine's own traffic allowance and
// threshold. Zero (or an empty field) clears that value so the machine follows
// its account group's allowance and the global threshold again.
func (s *Server) setInstanceTrafficLimit(w http.ResponseWriter, data map[string]any) {
	id := int64(number(data["accountId"], 0))
	a, err := s.Store.Account(id, false)
	if err != nil {
		s.error(w, 404, "实例不存在")
		return
	}
	limit := numberFloat(data["maxTraffic"])
	threshold := numberFloat(data["threshold"])
	if math.IsNaN(limit) || limit < 0 || limit > 1000000 {
		s.error(w, 400, "可用流量必须在 0 到 1000000 GB 之间（0 表示跟随账号）")
		return
	}
	if math.IsNaN(threshold) || threshold < 0 || threshold > 100 {
		s.error(w, 400, "流量阈值必须在 0 到 100 之间（0 表示跟随全局）")
		return
	}
	if err := s.Store.SetTrafficOverride(id, limit, threshold); err != nil {
		s.error(w, 500, "保存失败: "+err.Error())
		return
	}
	limitText, thresholdText := "跟随账号", "跟随全局"
	if limit > 0 {
		limitText = fmt.Sprintf("%g GB", limit)
	}
	if threshold > 0 {
		thresholdText = fmt.Sprintf("%g%%", threshold)
	}
	s.Store.AddLog("info", fmt.Sprintf("%s 的流量保护已设为：可用流量 %s，阈值 %s", accountDisplay(*a), limitText, thresholdText))
	s.json(w, 200, map[string]any{"success": true, "message": "流量保护设置已保存，下次检测时生效"})
}
