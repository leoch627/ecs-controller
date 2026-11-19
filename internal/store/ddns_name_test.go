package store

import (
	"testing"

	"github.com/Kori1c/ecs-controller/internal/app"
)

func TestLegacyInstanceDNSNameDerivation(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetSetting("ddns_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	aws := app.Account{AccessKeyID: "AKIA", RegionID: "ap-northeast-1", GroupKey: "g-aws", Remark: "AWS Tokyo", SiteType: "aws", InstanceID: "Debian-1", InstanceName: "Debian-1"}
	aliyun := app.Account{AccessKeyID: "LTAI", RegionID: "cn-hongkong", GroupKey: "g-ali", Remark: "hk", SiteType: "international", InstanceID: "i-abc", InstanceName: "web"}
	accounts := []app.Account{aws, aliyun}

	// An AWS machine is named after itself even when it is alone in its account.
	if got := s.DDNSNameForDomain(aws, accounts, s.CustomDNSName(aws), "example.com"); got != "aws-tokyo-debian-1.example.com" {
		t.Fatalf("aws name=%s", got)
	}
	// Alibaba Cloud keeps the existing scheme.
	if got := s.DDNSNameForDomain(aliyun, accounts, s.CustomDNSName(aliyun), "example.com"); got != "hk.example.com" {
		t.Fatalf("aliyun name=%s", got)
	}

	if err := s.SetCustomDNSName(aws, "jp1"); err != nil {
		t.Fatal(err)
	}
	if got := s.DDNSNameForDomain(aws, accounts, s.CustomDNSName(aws), "example.com"); got != "jp1.example.com" {
		t.Fatalf("custom name=%s", got)
	}
	// The cleanup payload carries only identity fields; the name must still resolve.
	payload := app.Account{AccessKeyID: aws.AccessKeyID, RegionID: aws.RegionID, InstanceID: aws.InstanceID, SiteType: "aws"}
	if got := s.DDNSNameForDomain(payload, nil, s.CustomDNSName(payload), "example.com"); got != "jp1.example.com" {
		t.Fatalf("payload name=%s", got)
	}
	if err := s.SetCustomDNSName(aws, ""); err != nil {
		t.Fatal(err)
	}
	if got := s.CustomDNSName(aws); got != "" {
		t.Fatalf("custom name was not cleared: %s", got)
	}
}

func TestNormalizeDNSName(t *testing.T) {
	for input, want := range map[string]string{
		"JP1":                  "jp1",
		" jp1.example.com. ":   "jp1",
		"node.jp1":             "node.jp1",
		"":                     "",
		"node.jp1.example.com": "node.jp1",
	} {
		got, err := NormalizeDNSName(input, "example.com")
		if err != nil || got != want {
			t.Errorf("NormalizeDNSName(%q)=%q,%v want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"example.com", "-jp", "jp_1", "jp..1", "日本", "a b"} {
		if _, err := NormalizeDNSName(input, "example.com"); err == nil {
			t.Errorf("NormalizeDNSName(%q) should fail", input)
		}
	}
}
