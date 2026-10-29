package worker

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
)

func poolRecords(cf *fakeCloudflare, name string) string {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	ips := []string{}
	for _, row := range cf.records {
		if recordName, ip, _ := strings.Cut(row, " "); recordName == name {
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	return strings.Join(ips, ",")
}

func TestDDNSPoolTracksRunningInstances(t *testing.T) {
	cf := &fakeCloudflare{records: map[string]string{"old": "rr.example.com 47.1.1.9", "hk": "hk.example.com 47.1.1.1"}}
	w, s := newCleanupWorker(t, cf)
	if err := s.SetSetting("ddns_pool_name", "rr"); err != nil {
		t.Fatal(err)
	}
	for i, account := range []app.Account{
		{InstanceID: "i-1", InstanceStatus: "Running", PublicIP: "47.1.1.1"},
		{InstanceID: "i-2", InstanceStatus: "Running", PublicIPMode: "eip", EIPAddress: "47.1.1.2"},
		{InstanceID: "i-3", InstanceStatus: "Running", PublicIP: "47.1.1.3"},
		{InstanceID: "i-4", InstanceStatus: "Stopped", PublicIP: "47.1.1.4"},
		{InstanceID: "i-5", InstanceStatus: "Running"},
	} {
		account.AccessKeyID, account.AccessKeySecret, account.RegionID, account.GroupKey = "ak", "sk", "cn-test", "g"+string(rune('1'+i))
		if err := s.UpsertAccount(account); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	w.syncDDNSPool(context.Background(), now)
	if got := poolRecords(cf, "rr.example.com"); got != "47.1.1.1,47.1.1.2,47.1.1.3" {
		t.Fatalf("pool records=%s", got)
	}
	if poolRecords(cf, "hk.example.com") != "47.1.1.1" {
		t.Fatalf("other records were touched: %v", cf.records)
	}

	// Nothing changed, so the provider is not called again.
	cf.fail = true
	w.syncDDNSPool(context.Background(), now.Add(time.Minute))
	if s.GetSetting("ddns_pool_retry_at", "0") != "0" {
		t.Fatal("an unchanged pool still called the provider")
	}

	// A stopped instance drops out; a failure backs off instead of retrying every tick.
	accounts, _ := s.LoadAccounts(false)
	for _, account := range accounts {
		if account.InstanceID == "i-3" {
			account.InstanceStatus = "Stopped"
			_ = s.UpsertAccount(account)
		}
	}
	w.syncDDNSPool(context.Background(), now.Add(2*time.Minute))
	if s.GetSetting("ddns_pool_retry_at", "0") == "0" {
		t.Fatal("a failed sync did not back off")
	}
	cf.fail = false
	w.syncDDNSPool(context.Background(), now.Add(3*time.Minute))
	if got := poolRecords(cf, "rr.example.com"); got != "47.1.1.1,47.1.1.2,47.1.1.3" {
		t.Fatalf("sync ran during back-off: %s", got)
	}
	w.syncDDNSPool(context.Background(), now.Add(13*time.Minute))
	if got := poolRecords(cf, "rr.example.com"); got != "47.1.1.1,47.1.1.2" {
		t.Fatalf("pool records after stop=%s", got)
	}
}
