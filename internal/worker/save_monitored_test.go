package worker

import (
	"testing"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/store"
)

func TestSaveMonitoredKeepsAnIPReplacedDuringThePass(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	loaded := app.Account{ID: 1, AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "ap-northeast-1", InstanceID: "i-1", InstanceStatus: "Running", PublicIP: "203.0.113.10", PublicIPMode: "eip", EIPAllocationID: "ip-old", EIPAddress: "203.0.113.10"}
	if err := st.UpsertAccount(loaded); err != nil {
		t.Fatal(err)
	}
	// The IP is replaced after the monitor loaded its copy of the row.
	if err := st.UpdateNetwork(1, map[string]any{"eip_allocation_id": "ip-new", "eip_address": "198.51.100.2", "public_ip": "198.51.100.2", "eip_managed": true}); err != nil {
		t.Fatal(err)
	}
	loaded.TrafficUsed = 12.5
	if err := (&Worker{Store: st}).saveMonitored(&loaded); err != nil {
		t.Fatal(err)
	}
	saved, err := st.Account(1, false)
	if err != nil {
		t.Fatal(err)
	}
	if saved.EIPAllocationID != "ip-new" || saved.PublicIP != "198.51.100.2" || saved.EIPAddress != "198.51.100.2" || !saved.EIPManaged {
		t.Fatalf("the monitor undid the replacement: %+v", saved)
	}
	if saved.TrafficUsed != 12.5 {
		t.Fatalf("the monitor's own update was lost: %+v", saved)
	}
}
