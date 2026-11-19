package worker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/dns"
	"github.com/Kori1c/ecs-controller/internal/store"
)

func saveRules(t *testing.T, s *store.Store, rules ...dns.Rule) {
	t.Helper()
	if rules == nil {
		rules = []dns.Rule{}
	}
	raw, _ := json.Marshal(rules)
	if err := s.SetSetting("ddns_rules", string(raw)); err != nil {
		t.Fatal(err)
	}
}

func rule(id, kind, domain, mode string) dns.Rule {
	return dns.Rule{ID: id, Enabled: true, Kind: kind, Provider: "cloudflare", Domain: domain, Name: "loadbalance", Scope: dns.MachineScope{Mode: mode}}
}

func multiDomainWorker(t *testing.T) (*Worker, *store.Store, *fakeCloudflare) {
	t.Helper()
	cf := &fakeCloudflare{records: map[string]string{}, zones: []map[string]any{{"id": "zone-1", "name": "example.com"}, {"id": "zone-2", "name": "other.net"}}}
	w, s := newCleanupWorker(t, cf)
	for _, a := range []app.Account{
		{AccessKeyID: "ali", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: "ali-group", SiteType: "international", Remark: "ali", InstanceID: "i-ali", InstanceStatus: "Running", PublicIP: "47.1.1.1"},
		{AccessKeyID: "aws", AccessKeySecret: "sk", RegionID: "ap-northeast-1", GroupKey: "aws-group", SiteType: "aws", Remark: "aws", InstanceName: "tokyo", InstanceID: "i-aws", InstanceStatus: "Running", PublicIP: "47.1.1.2"},
	} {
		if err := s.UpsertAccount(a); err != nil {
			t.Fatal(err)
		}
	}
	return w, s, cf
}

func TestMultiplePoolsSelectMachinesAndClearEmptyMembership(t *testing.T) {
	w, s, cf := multiDomainWorker(t)
	ali, aws := rule("ali", "pool", "example.com", "aliyun"), rule("aws", "pool", "other.net", "aws")
	saveRules(t, s, ali, aws)
	now := time.Now()
	w.syncDDNSPool(context.Background(), now)
	if got := poolRecords(cf, "loadbalance.example.com"); got != "47.1.1.1" {
		t.Fatal(got)
	}
	if got := poolRecords(cf, "loadbalance.other.net"); got != "47.1.1.2" {
		t.Fatal(got)
	}
	accounts, _ := s.LoadAccounts(false)
	for _, a := range accounts {
		if a.SiteType == "aws" {
			a.InstanceStatus = "Stopped"
			_ = s.UpsertAccount(a)
		}
	}
	w.syncDDNSPool(context.Background(), now.Add(time.Minute))
	if got := poolRecords(cf, "loadbalance.other.net"); got != "" {
		t.Fatalf("empty pool retained stopped IP: %s", got)
	}
	if got := poolRecords(cf, "loadbalance.example.com"); got != "47.1.1.1" {
		t.Fatal(got)
	}
	// A scope edit must bypass cached success even if an IP was unchanged.
	ali.Scope = dns.MachineScope{Mode: "instances", InstanceKeys: []string{"missing-machine"}}
	saveRules(t, s, ali, aws)
	w.syncDDNSPool(context.Background(), now.Add(2*time.Minute))
	if got := poolRecords(cf, "loadbalance.example.com"); got != "" {
		t.Fatalf("unselected machine stayed in pool: %s", got)
	}
}

func TestPoolFailureDoesNotBlockOtherDomains(t *testing.T) {
	w, s, cf := multiDomainWorker(t)
	saveRules(t, s, rule("ali", "pool", "example.com", "aliyun"), rule("aws", "pool", "other.net", "aws"))
	cf.failZone = "zone-1"
	w.syncDDNSPool(context.Background(), time.Now())
	if got := poolRecords(cf, "loadbalance.other.net"); got != "47.1.1.2" {
		t.Fatalf("other domain blocked: %s", got)
	}
	if s.GetSetting("ddns_rule_pool_ali_retry_at", "0") == "0" {
		t.Fatal("failed pool did not back off")
	}
}

func TestDomainMoveKeepsOldRecordUntilReplacementSucceeds(t *testing.T) {
	w, s, cf := multiDomainWorker(t)
	old := rule("ali", "pool", "example.com", "aliyun")
	saveRules(t, s, old)
	w.syncDDNSPool(context.Background(), time.Now())
	accounts, _ := s.LoadAccounts(false)
	bindings := s.DNSBindings(w.dnsSettings(), accounts)
	next := old
	next.Domain = "other.net"
	saveRules(t, s, next)
	raw, _ := json.Marshal(bindings)
	job := &store.Job{Payload: string(raw)}
	cf.failZone = "zone-2"
	if err := w.dnsRuleCleanupJob(context.Background(), job); err == nil {
		t.Fatal("failed replacement accepted")
	}
	if got := poolRecords(cf, "loadbalance.example.com"); got != "47.1.1.1" {
		t.Fatalf("old record removed too early: %s", got)
	}
	cf.failZone = ""
	w.syncDDNSPool(context.Background(), time.Now().Add(11*time.Minute))
	if err := w.dnsRuleCleanupJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if got := poolRecords(cf, "loadbalance.other.net"); got != "47.1.1.1" {
		t.Fatal(got)
	}
	if got := poolRecords(cf, "loadbalance.example.com"); got != "" {
		t.Fatalf("old domain retained: %s", got)
	}
}

func TestLegacyPoolExcludesAWSWithoutResaving(t *testing.T) {
	w, s, cf := multiDomainWorker(t)
	_ = s.SetSetting("ddns_pool_name", "loadbalance")
	cf.records["old-aws"] = "loadbalance.example.com 47.1.1.2"
	w.syncDDNSPool(context.Background(), time.Now())
	if got := poolRecords(cf, "loadbalance.example.com"); got != "47.1.1.1" {
		t.Fatalf("legacy membership: %s", got)
	}
}

func TestDeadIPCleanupOnlyUsesMatchingRuleDomains(t *testing.T) {
	w, s, cf := multiDomainWorker(t)
	saveRules(t, s, rule("ali", "pool", "example.com", "aliyun"), rule("aws", "pool", "other.net", "aws"))
	cf.records["ali"] = "loadbalance.example.com 47.1.1.9"
	cf.records["aws-manual"] = "manual.other.net 47.1.1.9"
	cf.records["unmanaged"] = "manual.unmanaged.org 47.1.1.9"
	accounts, _ := s.LoadAccounts(false)
	for _, a := range accounts {
		if a.SiteType != "aws" {
			a.PublicIP = "47.1.1.9"
			if queued, err := s.EnqueueAccountDNSCleanup(a, "ip_replaced"); err != nil || !queued {
				t.Fatalf("enqueue: %v %v", queued, err)
			}
		}
	}
	job, err := s.ClaimJob(time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: %v", err)
	}
	if err := w.dnsCleanupJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if got := poolRecords(cf, "loadbalance.example.com"); got != "" {
		t.Fatalf("stale IP retained: %s", got)
	}
	for _, name := range []string{"manual.other.net", "manual.unmanaged.org"} {
		if got := poolRecords(cf, name); got != "47.1.1.9" {
			t.Fatalf("cleanup escaped selected domain: %s=%s", name, got)
		}
	}
}

func TestUpgradeRetiresInstanceRecordsAndReconcilesTheLegacyPool(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "legacy settings"
		if explicit {
			name = "explicit rules"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			for key, value := range map[string]string{
				"ddns_enabled": "1", "ddns_provider": "cloudflare", "ddns_domain": "example.com",
				"ddns_cf_token": "fake-token", "ddns_pool_name": "loadbalance",
			} {
				if err := s.SetSetting(key, value); err != nil {
					t.Fatal(err)
				}
			}
			if explicit {
				instance := rule("singles", "instance", "example.com", "all")
				pool := rule("pool", "pool", "example.com", "aliyun")
				saveRules(t, s, instance, pool)
			}
			ali := app.Account{ID: 1, AccessKeyID: "ali", RegionID: "cn-test", SiteType: "international", Remark: "ali", InstanceID: "i-ali", InstanceStatus: "Running", PublicIP: "47.1.1.1"}
			aws := app.Account{ID: 2, AccessKeyID: "aws", RegionID: "ap-northeast-1", SiteType: "aws", Remark: "aws", InstanceName: "tokyo", InstanceID: "i-aws", InstanceStatus: "Running", PublicIP: "43.206.50.226"}
			for _, a := range []app.Account{ali, aws} {
				if err := s.UpsertAccount(a); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.SetCustomDNSName(aws, "tokyo-custom"); err != nil {
				t.Fatal(err)
			}
			gone := app.Account{AccessKeyID: "aws", RegionID: "other", SiteType: "aws", Remark: "aws", InstanceName: "gone", InstanceID: "i-gone"}
			if err := s.EnqueueJob("pending-from-old-version", "delete_ddns", "gone", map[string]any{"account": gone}); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			upgraded, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			s = upgraded
			if s.GetSetting("ddns_enabled", "1") != "0" {
				t.Fatal("legacy per-instance DNS was not disabled")
			}
			cf := &fakeCloudflare{records: map[string]string{
				"ali": "ali.example.com 47.1.1.1", "aws": "tokyo-custom.example.com 43.206.50.226",
				"gone": "aws-gone.example.com 43.199.143.244", "manual": "manual.example.com 43.206.50.226",
				"valid-pool": "loadbalance.example.com 47.1.1.1", "aws-pool": "loadbalance.example.com 43.206.50.226",
				"old-pool": "loadbalance.example.com 47.239.111.137",
			}}
			w := &Worker{Store: s, DNSClient: cf.client()}
			ctx := context.Background()
			for _, kind := range []string{"delete_ddns", "dns_rule_cleanup"} {
				job, err := s.ClaimJob(time.Minute)
				if err != nil || job == nil || job.Kind != kind {
					t.Fatalf("expected %s job, got %+v, %v", kind, job, err)
				}
				if err := w.execute(ctx, job); err != nil {
					t.Fatal(err)
				}
				if err := s.FinishJob(job.JobID); err != nil {
					t.Fatal(err)
				}
			}
			w.SyncAccountDNS(ctx, aws.ID)
			for _, host := range []string{"ali.example.com", "aws-tokyo.example.com", "aws-gone.example.com"} {
				if got := poolRecords(cf, host); got != "" {
					t.Fatalf("retired hostname %s still has A records: %s", host, got)
				}
			}
			if got := poolRecords(cf, "loadbalance.example.com"); got != "47.1.1.1" {
				t.Fatalf("pool contains stale addresses: %s", got)
			}
			if got := poolRecords(cf, "tokyo-custom.example.com"); got != "43.206.50.226" {
				t.Fatalf("explicit AWS API hostname changed: %s", got)
			}
			// A cleanup queued by the earlier version must also preserve it.
			old := rule("singles", "instance", "example.com", "all")
			payload, _ := json.Marshal([]store.DNSBinding{{Rule: old, Name: "tokyo-custom.example.com"}})
			if err := w.dnsRuleCleanupJob(ctx, &store.Job{Payload: string(payload)}); err != nil {
				t.Fatal(err)
			}
			if got := poolRecords(cf, "tokyo-custom.example.com"); got != "43.206.50.226" {
				t.Fatalf("old job deleted the explicit hostname: %s", got)
			}
			if got := poolRecords(cf, "manual.example.com"); got != "43.206.50.226" {
				t.Fatalf("unrelated record changed: %s", got)
			}
		})
	}
}
