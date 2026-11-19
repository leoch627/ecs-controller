package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/dns"
)

func TestIPWatchSwapsABlockedInstance(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)
	healthy := lightsailAccount()
	healthy.ID, healthy.InstanceID, healthy.InstanceName, healthy.PublicIP = 2, "i-2", "jp-2", "203.0.113.20"
	if err := st.UpsertAccount(healthy); err != nil {
		t.Fatal(err)
	}
	ipCheckFixture(t, st, 3, []string{"203.0.113.10"}, nil)

	srv.ipWatchRound(context.Background(), srv.ipCheckSettings(), time.Now())

	if got := fake.joined(); got != "allocate 198.51.100.1,associate ip-1" {
		t.Fatalf("calls=%s", got)
	}
	assertAccountNetwork(t, st, "ip-1", "198.51.100.1")
	if check := st.IPChecks()[2]; check.Status != ipCheckOK {
		t.Fatalf("healthy instance check=%+v", check)
	}
	if _, busy := srv.ipReplacing.Load(int64(1)); busy {
		t.Fatal("swap lock left behind")
	}
}

func TestIPWatchLeavesIPsAloneWhenMostAreBlocked(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)
	second := lightsailAccount()
	second.ID, second.InstanceID, second.InstanceName, second.PublicIP = 2, "i-2", "jp-2", "203.0.113.20"
	if err := st.UpsertAccount(second); err != nil {
		t.Fatal(err)
	}
	ipCheckFixture(t, st, 3, []string{"203.0.113.10", "203.0.113.20"}, nil)

	srv.ipWatchRound(context.Background(), srv.ipCheckSettings(), time.Now())

	if got := fake.joined(); got != "" {
		t.Fatalf("swapped although the probe looks broken: %s", got)
	}
	found := false
	for _, entry := range st.Logs("", 10) {
		message, _ := entry["message"].(string)
		found = found || strings.Contains(message, "疑似探测机网络问题")
	}
	if !found {
		t.Fatal("no warning about the probe")
	}
}

func TestIPWatchSkipsUnknownStoppedAndUnswappableInstances(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)
	stopped := lightsailAccount()
	stopped.ID, stopped.InstanceID, stopped.PublicIP, stopped.InstanceStatus = 2, "i-2", "203.0.113.20", "Stopped"
	noEIP := app.Account{ID: 3, AccessKeyID: "ali", AccessKeySecret: "sk", RegionID: "cn-hongkong", SiteType: "international", InstanceID: "i-3", InstanceStatus: "Running", PublicIP: "203.0.113.30", PublicIPMode: "ecs_public_ip"}
	for _, a := range []app.Account{stopped, noEIP} {
		if err := st.UpsertAccount(a); err != nil {
			t.Fatal(err)
		}
	}
	// Unreachable from both sides: the port is closed, not blocked.
	ipCheckFixture(t, st, 3, []string{"203.0.113.20", "203.0.113.30"}, []string{"203.0.113.10"})

	srv.ipWatchRound(context.Background(), srv.ipCheckSettings(), time.Now())

	if got := fake.joined(); got != "" {
		t.Fatalf("calls=%s", got)
	}
	checks := st.IPChecks()
	if checks[1].Status != ipCheckUnknown {
		t.Fatalf("check=%+v", checks[1])
	}
	if _, ok := checks[2]; ok {
		t.Fatal("stopped instance was checked")
	}
	if _, ok := checks[3]; ok {
		t.Fatal("instance without an EIP was checked")
	}
}

func TestIPWatchIntervalIsConfigurable(t *testing.T) {
	srv, _ := newReplaceIPServer(t, lightsailAccount(), &sequenceEIPClient{})
	if got := srv.ipCheckSettings().Interval; got != ipCheckDefaultInterval {
		t.Fatalf("default interval=%d", got)
	}
	if err := srv.saveIPCheckConfig(map[string]any{"port": 22, "max_swaps": 5, "auto_interval": 0}); err != nil {
		t.Fatal(err)
	}
	if got := srv.ipCheckSettings().Interval; got != 0 {
		t.Fatalf("interval=%d", got)
	}
	if err := srv.saveIPCheckConfig(map[string]any{"port": 22, "max_swaps": 5, "auto_interval": 5000}); err == nil {
		t.Fatal("out-of-range interval accepted")
	}
}

func TestIPWatchNeverTouchesExcludedInstances(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)
	ipCheckFixture(t, st, 3, []string{"203.0.113.10"}, nil)
	key := dns.InstanceKey(lightsailAccount())
	if err := srv.saveIPCheckConfig(map[string]any{"probe_url": srv.ipCheckSettings().ProbeURL, "port": 443, "max_swaps": 3, "auto_interval": 20, "auto_exclude": []any{key}}); err != nil {
		t.Fatal(err)
	}
	if got := srv.ipCheckConfig()["auto_exclude"].([]string); len(got) != 1 || got[0] != key {
		t.Fatalf("round trip: %v", got)
	}

	srv.ipWatchRound(context.Background(), srv.ipCheckSettings(), time.Now())

	if got := fake.joined(); got != "" {
		t.Fatalf("excluded instance swapped: %s", got)
	}
	if _, ok := st.IPChecks()[1]; ok {
		t.Fatal("excluded instance was checked")
	}
	if err := srv.saveIPCheckConfig(map[string]any{"port": 443, "max_swaps": 3, "auto_exclude": []any{"not-a-key"}}); err == nil {
		t.Fatal("invalid key accepted")
	}
}
