package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/store"
)

type fakeEIPClient struct {
	cloud.Client
	current  cloud.EIPDetail
	statuses []string // statuses reported for the old EIP after it is unbound
	unbound  bool
	template *cloud.EIPDetail
	calls    []string
}

func (f *fakeEIPClient) DescribeEIP(_ context.Context, _ string, allocationID string) (*cloud.EIPDetail, error) {
	f.calls = append(f.calls, "describe")
	eip := f.current
	if f.unbound {
		eip.InstanceID, eip.Status = "", "Available"
		if len(f.statuses) > 0 {
			eip.Status, f.statuses = f.statuses[0], f.statuses[1:]
		}
	}
	return &eip, nil
}

func (f *fakeEIPClient) AllocateEIPLike(_ context.Context, _ string, template cloud.EIPDetail) (string, string, error) {
	f.calls = append(f.calls, "allocate")
	f.template = &template
	return "eip-new", "198.51.100.20", nil
}

func (f *fakeEIPClient) UnassociateEIP(_ context.Context, _ string, allocationID string) error {
	f.calls = append(f.calls, "unassociate "+allocationID)
	f.unbound = true
	return nil
}

func (f *fakeEIPClient) AssociateEIP(_ context.Context, _ string, allocationID, _ string) error {
	f.calls = append(f.calls, "associate "+allocationID)
	return nil
}

func (f *fakeEIPClient) ReleaseEIP(_ context.Context, _ string, allocationID string) error {
	f.calls = append(f.calls, "release "+allocationID)
	return nil
}

func newReplaceIPServer(t *testing.T, account app.Account, client cloud.Client) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpsertAccount(account); err != nil {
		t.Fatal(err)
	}
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	srv.CloudFactory = func(app.Account) cloud.Client { return client }
	return srv, st
}

func selfBoundEIPAccount() app.Account {
	return app.Account{ID: 1, AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-hongkong", InstanceID: "i-1", InstanceStatus: "Running", PublicIP: "203.0.113.10", PublicIPMode: "eip", EIPAllocationID: "eip-old", EIPAddress: "203.0.113.10", InternetBandwidth: 10}
}

func TestReplaceIPSwapsSelfBoundEIPWithMatchingReplacement(t *testing.T) {
	previous := eipPollInterval
	eipPollInterval = time.Millisecond
	t.Cleanup(func() { eipPollInterval = previous })

	fake := &fakeEIPClient{
		current:  cloud.EIPDetail{AllocationID: "eip-old", Address: "203.0.113.10", Status: "InUse", InstanceID: "i-1", Bandwidth: 50, InternetChargeType: "PayByBandwidth", ChargeType: "PostPaid", ISP: "BGP_PRO"},
		statuses: []string{"Unassociating", "Unassociating"},
	}
	srv, st := newReplaceIPServer(t, selfBoundEIPAccount(), fake)
	if err := st.SetSetting("dns_cleanup_enabled", "1"); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	srv.replaceIP(recorder, map[string]any{"accountId": 1})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if fake.template == nil || fake.template.Bandwidth != 50 || fake.template.InternetChargeType != "PayByBandwidth" || fake.template.ISP != "BGP_PRO" {
		t.Fatalf("replacement did not copy the old EIP: %#v", fake.template)
	}
	want := "describe,allocate,unassociate eip-old,describe,describe,describe,associate eip-new,release eip-old"
	if got := strings.Join(fake.calls, ","); got != want {
		t.Fatalf("calls=%s\nwant=%s", got, want)
	}

	account, err := st.Account(1, false)
	if err != nil {
		t.Fatal(err)
	}
	if account.EIPAllocationID != "eip-new" || account.PublicIP != "198.51.100.20" || !account.EIPManaged || account.InternetBandwidth != 50 {
		t.Fatalf("account network=%+v", account)
	}
	jobs, err := st.ListJobs(store.DNSCleanupKind, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].EntityKey != "203.0.113.10" {
		t.Fatalf("old IP was not queued for DNS cleanup: %#v", jobs)
	}
}

func TestReplaceIPRefusesEIPsThatCannotBeReleased(t *testing.T) {
	for name, eip := range map[string]cloud.EIPDetail{
		"prepaid":             {ChargeType: "PrePaid"},
		"bandwidth package":   {BandwidthPackageID: "cbwp-1"},
		"deletion protection": {DeletionProtection: true},
		"other instance":      {InstanceID: "i-other"},
	} {
		t.Run(name, func(t *testing.T) {
			eip.AllocationID, eip.Status = "eip-old", "InUse"
			fake := &fakeEIPClient{current: eip}
			srv, st := newReplaceIPServer(t, selfBoundEIPAccount(), fake)
			recorder := httptest.NewRecorder()
			srv.replaceIP(recorder, map[string]any{"accountId": 1})
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if got := strings.Join(fake.calls, ","); got != "describe" {
				t.Fatalf("refused swap still touched the cloud: %s", got)
			}
			if account, _ := st.Account(1, false); account.EIPAllocationID != "eip-old" {
				t.Fatalf("refused swap changed the account: %+v", account)
			}
		})
	}
}

func TestReplaceIPRejectsInstanceWithoutEIP(t *testing.T) {
	account := selfBoundEIPAccount()
	account.PublicIPMode, account.EIPAllocationID, account.EIPAddress = "ecs_public_ip", "", ""
	fake := &fakeEIPClient{}
	srv, _ := newReplaceIPServer(t, account, fake)
	recorder := httptest.NewRecorder()
	srv.replaceIP(recorder, map[string]any{"accountId": 1})
	if recorder.Code != http.StatusBadRequest || len(fake.calls) != 0 {
		t.Fatalf("status=%d calls=%v body=%s", recorder.Code, fake.calls, recorder.Body.String())
	}
}
