package worker

import (
	"context"
	"testing"

	"github.com/Kori1c/ecs-controller/internal/app"
)

func TestSyncAccountDNSPointsRecordsAtTheNewIP(t *testing.T) {
	cf := &fakeCloudflare{records: map[string]string{"a": "tokyo.example.com 203.0.113.10", "b": "rr.example.com 203.0.113.10"}}
	w, s := newCleanupWorker(t, cf)
	for key, value := range map[string]string{"ddns_enabled": "1", "ddns_pool_name": "rr"} {
		if err := s.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	account := app.Account{ID: 1, AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "ap-northeast-1", GroupKey: "g1", Remark: "tokyo", InstanceID: "i-1", InstanceStatus: "Running", PublicIPMode: "eip", EIPAllocationID: "ip-new", EIPAddress: "198.51.100.2", PublicIP: "198.51.100.2"}
	if err := s.UpsertAccount(account); err != nil {
		t.Fatal(err)
	}

	w.SyncAccountDNS(context.Background(), 1)
	if got := poolRecords(cf, "tokyo.example.com"); got != "198.51.100.2" {
		t.Fatalf("DDNS record=%s", got)
	}
	if got := poolRecords(cf, "rr.example.com"); got != "198.51.100.2" {
		t.Fatalf("pool record=%s", got)
	}
	if s.GetSetting("last_ddns_reconcile", "") == "0" {
		t.Fatal("a successful sync should not schedule a retry")
	}

	// A failed update is retried on the monitor's next pass.
	cf.fail = true
	if err := s.UpdateNetwork(1, map[string]any{"eip_address": "198.51.100.3", "public_ip": "198.51.100.3"}); err != nil {
		t.Fatal(err)
	}
	w.SyncAccountDNS(context.Background(), 1)
	if s.GetSetting("last_ddns_reconcile", "") != "0" {
		t.Fatal("a failed sync should be retried by the monitor")
	}
}
