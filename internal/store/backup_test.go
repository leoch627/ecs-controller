package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Kori1c/ecs-controller/internal/app"
)

func TestSnapshotAndRestoreKeepsDurableDataAndDropsRuntimeState(t *testing.T) {
	source, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := source.SetSetting("app_name", "示例控制台"); err != nil {
		t.Fatal(err)
	}
	if err := source.SaveGroups([]app.AccountGroup{{GroupKey: "group-a", AccessKeyID: "ak", AccessKeySecret: "secret", RegionID: "cn-hongkong", MaxTraffic: 200}}); err != nil {
		t.Fatal(err)
	}
	if err := source.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "secret", RegionID: "cn-hongkong", GroupKey: "group-a", InstanceID: "i-source", InstanceStatus: "Running"}); err != nil {
		t.Fatal(err)
	}
	if err := source.SavePasskeyCredential("credential", `{"id":"credential"}`); err != nil {
		t.Fatal(err)
	}

	snapshot := filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := source.Snapshot(snapshot); err != nil {
		t.Fatal(err)
	}

	target, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.SetSetting("app_name", "旧控制台"); err != nil {
		t.Fatal(err)
	}
	if err := target.CreateSession("runtime-session", "csrf", 0); err != nil {
		t.Fatal(err)
	}
	if err := target.RestoreSnapshot(snapshot, source.EncryptionKey()); err != nil {
		t.Fatal(err)
	}
	if got := target.GetSetting("app_name", ""); got != "示例控制台" {
		t.Fatalf("app name=%q, want restored value", got)
	}
	groups, err := target.LoadGroups()
	if err != nil || len(groups) != 1 || groups[0].AccessKeySecret != "secret" {
		t.Fatalf("groups=%#v err=%v", groups, err)
	}
	accounts, err := target.LoadAccounts(false)
	if err != nil || len(accounts) != 1 || accounts[0].InstanceID != "i-source" {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
	if target.PasskeyCount() != 1 {
		t.Fatalf("passkey count=%d, want 1", target.PasskeyCount())
	}
	if _, ok := target.Session("runtime-session"); ok {
		t.Fatal("runtime session was restored")
	}
}

func TestRestoreAcceptsSnapshotWithoutNewerColumns(t *testing.T) {
	source, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := source.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "secret", RegionID: "cn-hongkong", GroupKey: "group-a", InstanceID: "i-old", MaxTraffic: 180}); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := source.Snapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	// Simulate a backup taken before the per-instance override columns existed.
	old, err := sql.Open("sqlite", "file:"+filepath.ToSlash(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"traffic_limit_override", "traffic_threshold_override"} {
		if _, err := old.Exec(`ALTER TABLE accounts DROP COLUMN ` + column); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()

	target, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.RestoreSnapshot(snapshot, source.EncryptionKey()); err != nil {
		t.Fatal(err)
	}
	accounts, err := target.LoadAccounts(false)
	if err != nil || len(accounts) != 1 || accounts[0].InstanceID != "i-old" || accounts[0].MaxTraffic != 180 || accounts[0].TrafficLimitOverride != 0 {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
	if err := target.SetTrafficOverride(accounts[0].ID, 90, 85); err != nil {
		t.Fatal(err)
	}
	roundTrip := filepath.Join(t.TempDir(), "round-trip.sqlite")
	if err := target.Snapshot(roundTrip); err != nil {
		t.Fatal(err)
	}
	if err := source.RestoreSnapshot(roundTrip, target.EncryptionKey()); err != nil {
		t.Fatal(err)
	}
	if got, err := source.Account(accounts[0].ID, false); err != nil || got.TrafficLimitOverride != 90 || got.TrafficThresholdOverride != 85 {
		t.Fatalf("override not restored: %+v %v", got, err)
	}
}
