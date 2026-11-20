package worker

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
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

func namesWorker(t *testing.T) (*Worker, *store.Store, *fakeCloudflare, []app.Account) {
	t.Helper()
	cf := &fakeCloudflare{records: map[string]string{}, zones: []map[string]any{{"id": "zone-1", "name": "example.com"}, {"id": "zone-2", "name": "other.net"}}}
	w, s := newCleanupWorker(t, cf)
	if err := s.SetSetting("ddns_domains", `[{"id":"d1","provider":"cloudflare","domain":"example.com"},{"id":"d2","provider":"cloudflare","domain":"other.net"}]`); err != nil {
		t.Fatal(err)
	}
	accounts := []app.Account{
		{ID: 1, AccessKeyID: "ali", AccessKeySecret: "sk", RegionID: "cn-hongkong", SiteType: "international", Remark: "hk1", InstanceID: "i-1", InstanceStatus: "Running", PublicIP: "47.1.1.1"},
		{ID: 2, AccessKeyID: "ali", AccessKeySecret: "sk", RegionID: "cn-hongkong", SiteType: "international", Remark: "hk2", InstanceID: "i-2", InstanceStatus: "Running", PublicIP: "47.1.1.2"},
		{ID: 3, AccessKeyID: "aws", AccessKeySecret: "sk", RegionID: "ap-northeast-1", SiteType: "aws", Remark: "tokyo", InstanceID: "i-3", InstanceStatus: "Running", PublicIP: "13.1.1.3"},
	}
	for _, a := range accounts {
		if err := s.UpsertAccount(a); err != nil {
			t.Fatal(err)
		}
	}
	return w, s, cf, accounts
}

func setNames(t *testing.T, s *store.Store, a app.Account, names ...string) {
	t.Helper()
	if err := s.SetDNSHostNames(a, names); err != nil {
		t.Fatal(err)
	}
}

func TestSharedNameIsRoundRobinAndOwnNameIsDDNS(t *testing.T) {
	w, s, cf, accounts := namesWorker(t)
	setNames(t, s, accounts[0], "lb.example.com", "hk1.example.com")
	setNames(t, s, accounts[1], "lb.example.com")
	setNames(t, s, accounts[2], "api.other.net")
	now := time.Now()
	w.syncDNSNames(context.Background(), now)
	for name, want := range map[string]string{"lb.example.com": "47.1.1.1,47.1.1.2", "hk1.example.com": "47.1.1.1", "api.other.net": "13.1.1.3"} {
		if got := poolRecords(cf, name); got != want {
			t.Fatalf("%s=%s want %s", name, got, want)
		}
	}

	// IP swap: the machine's own name and the shared one both follow it.
	if err := s.UpdateNetwork(1, map[string]any{"public_ip": "47.1.1.9"}); err != nil {
		t.Fatal(err)
	}
	w.SyncAccountDNS(context.Background(), 1)
	if got := poolRecords(cf, "hk1.example.com"); got != "47.1.1.9" {
		t.Fatalf("own name after swap=%s", got)
	}
	if got := poolRecords(cf, "lb.example.com"); got != "47.1.1.2,47.1.1.9" {
		t.Fatalf("shared name after swap=%s", got)
	}

	// A stopped machine leaves the shared name but keeps its own record.
	stopped := accounts[1]
	stopped.InstanceStatus = "Stopped"
	if err := s.UpsertAccount(stopped); err != nil {
		t.Fatal(err)
	}
	aws := accounts[2]
	aws.InstanceStatus = "Stopped"
	if err := s.UpsertAccount(aws); err != nil {
		t.Fatal(err)
	}
	w.syncDNSNames(context.Background(), now.Add(time.Minute))
	if got := poolRecords(cf, "lb.example.com"); got != "47.1.1.9" {
		t.Fatalf("stopped machine stayed in shared name: %s", got)
	}
	if got := poolRecords(cf, "api.other.net"); got != "13.1.1.3" {
		t.Fatalf("stopped machine lost its own record: %s", got)
	}
}

func TestMachinesWithoutNamesJoinNothing(t *testing.T) {
	w, s, cf, accounts := namesWorker(t)
	setNames(t, s, accounts[0], "lb.example.com")
	w.syncDNSNames(context.Background(), time.Now())
	if got := poolRecords(cf, "lb.example.com"); got != "47.1.1.1" {
		t.Fatalf("lb=%s", got)
	}
	if len(cf.records) != 1 {
		t.Fatalf("machines without names got records: %v", cf.records)
	}
}

func TestDroppedNameIsDeletedOnlyWhenNobodyHoldsIt(t *testing.T) {
	w, s, cf, accounts := namesWorker(t)
	setNames(t, s, accounts[0], "lb.example.com", "old.example.com")
	setNames(t, s, accounts[1], "lb.example.com")
	now := time.Now()
	w.syncDNSNames(context.Background(), now)

	setNames(t, s, accounts[0])
	w.syncDNSNames(context.Background(), now.Add(time.Minute))
	if got := poolRecords(cf, "old.example.com"); got != "" {
		t.Fatalf("dropped name still resolves: %s", got)
	}
	if got := poolRecords(cf, "lb.example.com"); got != "47.1.1.2" {
		t.Fatalf("shared name=%s", got)
	}
	if _, ok := s.DNSManaged()["old.example.com"]; ok {
		t.Fatal("deleted name is still managed")
	}

	// A machine that disappears from the cloud gives up its names too.
	if err := s.DeleteInstanceData(2); err != nil {
		t.Fatal(err)
	}
	w.syncDNSNames(context.Background(), now.Add(2*time.Minute))
	if got := poolRecords(cf, "lb.example.com"); got != "" {
		t.Fatalf("name of a vanished machine still resolves: %s", got)
	}
}

func TestFailingDomainBacksOffWithoutBlockingOthers(t *testing.T) {
	w, s, cf, accounts := namesWorker(t)
	setNames(t, s, accounts[0], "lb.example.com")
	setNames(t, s, accounts[2], "api.other.net")
	cf.failZone = "zone-1"
	now := time.Now()
	w.syncDNSNames(context.Background(), now)
	if got := poolRecords(cf, "api.other.net"); got != "13.1.1.3" {
		t.Fatalf("other domain blocked: %s", got)
	}
	if s.DNSManaged()["lb.example.com"].RetryAt == 0 {
		t.Fatal("failure did not back off")
	}
	cf.failZone = ""
	w.syncDNSNames(context.Background(), now.Add(time.Minute))
	if got := poolRecords(cf, "lb.example.com"); got != "" {
		t.Fatalf("retried before the backoff: %s", got)
	}
	w.syncDNSNames(context.Background(), now.Add(poolRetryDelay+time.Minute))
	if got := poolRecords(cf, "lb.example.com"); got != "47.1.1.1" {
		t.Fatalf("after backoff=%s", got)
	}
}

func TestUpgradeGivesEachMachineTheNamesItsRulesGaveIt(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ali := app.Account{ID: 1, AccessKeyID: "ali", RegionID: "cn-hongkong", SiteType: "international", Remark: "hk", InstanceID: "i-ali", InstanceStatus: "Running", PublicIP: "47.1.1.1"}
	aws := app.Account{ID: 2, AccessKeyID: "aws", RegionID: "ap-northeast-1", SiteType: "aws", Remark: "aws", InstanceName: "tokyo", InstanceID: "i-aws", InstanceStatus: "Running", PublicIP: "13.1.1.2"}
	plain := app.Account{ID: 3, AccessKeyID: "aws", RegionID: "ap-east-1", SiteType: "aws", Remark: "aws2", InstanceName: "hk", InstanceID: "i-plain", InstanceStatus: "Running", PublicIP: "13.1.1.3"}
	for _, a := range []app.Account{ali, aws, plain} {
		if err := s.UpsertAccount(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetCustomDNSName(aws, "api-nrt"); err != nil {
		t.Fatal(err)
	}
	rules, _ := json.Marshal([]dns.Rule{
		{ID: "legacy-pool", Enabled: true, Kind: "pool", Provider: "cloudflare", Domain: "example.com", Name: "loadbalance", Scope: dns.MachineScope{Mode: "aliyun"}},
		{ID: "legacy-instance", Enabled: true, Kind: "instance", Provider: "cloudflare", Domain: "example.com", Scope: dns.MachineScope{Mode: "instances", InstanceKeys: []string{dns.InstanceKey(aws)}}},
	})
	for key, value := range map[string]string{"ddns_rules": string(rules), "ddns_domains": ""} {
		if err := s.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`DELETE FROM settings WHERE key='ddns_domains'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err = store.Open(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	settings := dns.LoadSettings(s.GetSetting, nil)
	if len(settings.Domains) != 1 || settings.Domains[0].Domain != "example.com" || settings.Domains[0].Provider != "cloudflare" {
		t.Fatalf("domains=%+v", settings.Domains)
	}
	for account, want := range map[app.Account]string{ali: "loadbalance.example.com", aws: "api-nrt.example.com", plain: ""} {
		if got := strings.Join(s.DNSHostNames(account), ","); got != want {
			t.Fatalf("%s names=%q want %q", account.InstanceID, got, want)
		}
	}
	if _, ok := s.DNSManaged()["api-nrt.example.com"]; !ok {
		t.Fatal("migrated names are not managed")
	}
}
