package notify

import (
	"testing"
	"time"
)

func TestEventTextUsesSharedLayout(t *testing.T) {
	event := Event{
		Title: "公网 IP 已更换",
		Lines: append(InstanceLines("香港1", "i-abc", "cn-hongkong"), L("旧 IP", "1.1.1.1"), L("新 IP", ""), L("说明", "ok")),
		Body:  "附加内容",
		Time:  time.Date(2026, 11, 19, 8, 30, 0, 0, time.Local),
	}
	want := "【ECS 控制台】公网 IP 已更换\n实例: 香港1\n实例 ID: i-abc\n区域: cn-hongkong\n旧 IP: 1.1.1.1\n说明: ok\n时间: 2026-11-19 08:30:00\n\n附加内容"
	if got := event.Text(); got != want {
		t.Fatalf("unexpected text:\n%s\nwant:\n%s", got, want)
	}
}

func TestInstanceLinesSkipsIDWhenItIsTheName(t *testing.T) {
	lines := InstanceLines("i-abc", "i-abc", "cn-hongkong")
	if len(lines) != 2 || lines[0].Label != "实例" || lines[1].Label != "区域" {
		t.Fatalf("unexpected lines: %#v", lines)
	}
}
