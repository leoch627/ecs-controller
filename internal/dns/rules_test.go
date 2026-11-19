package dns

import (
	"testing"

	"github.com/Kori1c/ecs-controller/internal/app"
)

func TestMachineScopesDoNotWidenEmptyOrUnknownSelections(t *testing.T) {
	ali := app.Account{AccessKeyID: "ak", RegionID: "cn-test", InstanceID: "i-1", GroupKey: "group", SiteType: "international"}
	aws := ali
	aws.SiteType = "aws"
	aws.InstanceID = "lightsail"
	for _, tc := range []struct {
		scope    MachineScope
		ali, aws bool
	}{
		{MachineScope{Mode: "aliyun"}, true, false},
		{MachineScope{Mode: "aws"}, false, true},
		{MachineScope{Mode: "all"}, true, true},
		{MachineScope{Mode: "groups", GroupKeys: []string{"group"}}, true, true},
		{MachineScope{Mode: "instances", InstanceKeys: []string{InstanceKey(ali)}}, true, false},
		{MachineScope{Mode: "groups"}, false, false},
		{MachineScope{Mode: "instances"}, false, false},
		{MachineScope{Mode: "typo"}, false, false},
	} {
		if tc.scope.Matches(ali) != tc.ali || tc.scope.Matches(aws) != tc.aws {
			t.Fatalf("scope %+v", tc.scope)
		}
	}
	ali.SiteType = "china"
	if !(MachineScope{Mode: "aliyun"}).Matches(ali) {
		t.Fatal("China site excluded")
	}
	before := InstanceKey(ali)
	ali.ID = 999
	ali.PublicIP = "47.2.2.2"
	if InstanceKey(ali) != before {
		t.Fatal("selection changed after inventory/IP update")
	}
}

func TestRuleSettingsKeepZonesAndCredentialsIndependent(t *testing.T) {
	s := Settings{Provider: "cloudflare", Domain: "old.test", Credentials: map[string]Config{"cloudflare": {"token": "secret", "zone_id": "old-zone"}}}
	r := Rule{ID: "a", Enabled: true, Kind: "pool", Provider: "cloudflare", Domain: "other.test", Name: "@", Scope: MachineScope{Mode: "aliyun"}}
	scoped := s.ForRule(r)
	if scoped.PoolFQDN() != "other.test" || scoped.Credentials["cloudflare"]["zone_id"] != "" {
		t.Fatalf("wrong domain/zone: %+v", scoped)
	}
	if s.Credentials["cloudflare"]["zone_id"] != "old-zone" {
		t.Fatal("mutated global credentials")
	}
	r.ZoneID = "other-zone"
	if s.ForRule(r).Credentials["cloudflare"]["zone_id"] != "other-zone" {
		t.Fatal("rule zone ignored")
	}
}

func TestLegacyPoolsDefaultToAliyunAndExplicitEmptyRulesStayEmpty(t *testing.T) {
	s := Settings{Domain: "example.com", Provider: "cloudflare", PoolName: "rr", DDNSEnabled: true}
	rules := s.EffectiveRules()
	if len(rules) != 2 || rules[1].Scope.Mode != "aliyun" {
		t.Fatalf("legacy rules: %+v", rules)
	}
	s.RulesConfigured = true
	if len(s.EffectiveRules()) != 0 {
		t.Fatal("empty rules fell back to global domain")
	}
}

func TestRuleValidation(t *testing.T) {
	base := Rule{ID: "a", Enabled: true, Kind: "pool", Provider: "cloudflare", Domain: "https://Example.COM/", Name: "rr", Scope: MachineScope{Mode: "aliyun"}}
	rules := []Rule{base}
	if err := ValidateRules(rules); err != nil || rules[0].FQDN() != "rr.example.com" {
		t.Fatalf("normalization: %+v %v", rules, err)
	}
	for _, change := range []func(*Rule){
		func(r *Rule) { r.Domain = "bad:443" }, func(r *Rule) { r.Name = "bad_name" },
		func(r *Rule) { r.Scope.Mode = "" }, func(r *Rule) { r.Scope = MachineScope{Mode: "instances"} },
		func(r *Rule) { r.Kind = "typo" }, func(r *Rule) { r.Provider = "typo" },
	} {
		r := base
		change(&r)
		if err := ValidateRules([]Rule{r}); err == nil {
			t.Fatalf("accepted invalid rule: %+v", r)
		}
	}
	other := base
	other.ID = "b"
	if err := ValidateRules([]Rule{base, other}); err == nil {
		t.Fatal("duplicate target accepted")
	}
}
