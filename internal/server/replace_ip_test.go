package server

import (
	"context"
	"errors"
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
	current     cloud.EIPDetail
	statuses    []string // statuses reported for the old EIP after it is unbound
	unbound     bool
	released    map[string]bool
	template    *cloud.EIPDetail
	allocateErr error // fails allocation with the old EIP's line
	fallbackErr error // fails allocation with default settings
	associate   map[string]error
	release     map[string]error
	calls       []string
}

// GetInstanceMonthlyTraffic reports 300 GiB on the old IP and nothing else.
func (f *fakeEIPClient) GetInstanceMonthlyTraffic(_ context.Context, _, _, ip string, _, _ int64) (float64, int, error) {
	f.calls = append(f.calls, "traffic "+ip)
	if ip == "203.0.113.10" {
		return 300 * 1024 * 1024 * 1024, 1, nil
	}
	return 0, 0, nil
}

func (f *fakeEIPClient) DescribeEIP(_ context.Context, _ string, allocationID string) (*cloud.EIPDetail, error) {
	f.calls = append(f.calls, "describe")
	if f.released[allocationID] || f.current.AllocationID == "" {
		return nil, &cloud.APIError{Code: "InvalidAllocationId.NotFound", HTTPStatus: 404}
	}
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
	if f.allocateErr != nil {
		return "", "", f.allocateErr
	}
	return "eip-new", "198.51.100.20", nil
}

func (f *fakeEIPClient) AllocateEIPWithBandwidth(_ context.Context, _ string, bandwidth int) (string, string, error) {
	f.calls = append(f.calls, "allocate default")
	if f.fallbackErr != nil {
		return "", "", f.fallbackErr
	}
	return "eip-new", "198.51.100.20", nil
}

func (f *fakeEIPClient) UnassociateEIP(_ context.Context, _ string, allocationID string) error {
	f.calls = append(f.calls, "unassociate "+allocationID)
	f.unbound = true
	return nil
}

func (f *fakeEIPClient) AssociateEIP(_ context.Context, _ string, allocationID, _ string) error {
	f.calls = append(f.calls, "associate "+allocationID)
	return f.associate[allocationID]
}

func (f *fakeEIPClient) ReleaseEIP(_ context.Context, _ string, allocationID string) error {
	f.calls = append(f.calls, "release "+allocationID)
	if err := f.release[allocationID]; err != nil {
		return err
	}
	if f.released == nil {
		f.released = map[string]bool{}
	}
	f.released[allocationID] = true
	return nil
}

func newReplaceIPServer(t *testing.T, account app.Account, client cloud.Client) (*Server, *store.Store) {
	t.Helper()
	previous := eipPollInterval
	eipPollInterval = time.Millisecond
	t.Cleanup(func() { eipPollInterval = previous })
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpsertAccount(account); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("dns_cleanup_enabled", "1"); err != nil {
		t.Fatal(err)
	}
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	srv.CloudFactory = func(app.Account) cloud.Client { return client }
	return srv, st
}

func selfBoundEIPAccount() app.Account {
	return app.Account{ID: 1, AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-hongkong", InstanceID: "i-1", InstanceStatus: "Running", PublicIP: "203.0.113.10", PublicIPMode: "eip", EIPAllocationID: "eip-old", EIPAddress: "203.0.113.10", InternetBandwidth: 10}
}

func boundEIP() cloud.EIPDetail {
	return cloud.EIPDetail{AllocationID: "eip-old", Address: "203.0.113.10", Status: "InUse", InstanceID: "i-1", Bandwidth: 5000, InternetChargeType: "PayByTraffic", ChargeType: "PostPaid", ISP: "BGP"}
}

func replaceIPFor(t *testing.T, srv *Server) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	srv.replaceIP(recorder, map[string]any{"accountId": 1})
	return recorder
}

func assertCalls(t *testing.T, fake *fakeEIPClient, want string) {
	t.Helper()
	if got := strings.Join(fake.calls, ","); got != want {
		t.Fatalf("calls=%s\nwant=%s", got, want)
	}
}

func assertAccountNetwork(t *testing.T, st *store.Store, allocationID, publicIP string) app.Account {
	t.Helper()
	account, err := st.Account(1, false)
	if err != nil {
		t.Fatal(err)
	}
	if account.EIPAllocationID != allocationID || account.PublicIP != publicIP || account.PublicIPMode != "eip" {
		t.Fatalf("account network=%+v, want allocation %q and IP %q", account, allocationID, publicIP)
	}
	return *account
}

func assertOldIPQueuedForDNSCleanup(t *testing.T, st *store.Store) {
	t.Helper()
	jobs, err := st.ListJobs(store.DNSCleanupKind, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].EntityKey != "203.0.113.10" {
		t.Fatalf("old IP was not queued for DNS cleanup: %#v", jobs)
	}
}

func TestReplaceIPReleasesOldEIPBeforeBindingNewOne(t *testing.T) {
	fake := &fakeEIPClient{current: boundEIP(), statuses: []string{"Unassociating", "Unassociating"}}
	srv, st := newReplaceIPServer(t, selfBoundEIPAccount(), fake)

	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertCalls(t, fake, "describe,traffic 203.0.113.10,unassociate eip-old,describe,describe,describe,release eip-old,allocate,associate eip-new")
	if fake.template == nil || fake.template.Bandwidth != 5000 || fake.template.ISP != "BGP" {
		t.Fatalf("replacement did not copy the old EIP: %#v", fake.template)
	}
	account := assertAccountNetwork(t, st, "eip-new", "198.51.100.20")
	if !account.EIPManaged || account.InternetBandwidth != 5000 {
		t.Fatalf("account network=%+v", account)
	}
	assertOldIPQueuedForDNSCleanup(t, st)
	sample, err := st.InstanceTrafficUsage(1, "i-1", time.Now().Format("2006-01"))
	if err != nil {
		t.Fatal(err)
	}
	if sample.RetiredBytes != 300*1024*1024*1024 || sample.IPSinceMS == 0 {
		t.Fatalf("old IP traffic was not carried over: %+v", sample)
	}
}

func TestReplaceIPFallsBackToDefaultLine(t *testing.T) {
	fake := &fakeEIPClient{current: boundEIP(), allocateErr: errors.New("InvalidParameter.ISP")}
	srv, st := newReplaceIPServer(t, selfBoundEIPAccount(), fake)

	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertCalls(t, fake, "describe,traffic 203.0.113.10,unassociate eip-old,describe,release eip-old,allocate,allocate default,associate eip-new")
	assertAccountNetwork(t, st, "eip-new", "198.51.100.20")
}

func TestReplaceIPCanBeRetriedAfterAllocationFails(t *testing.T) {
	quota := errors.New("QuotaExceeded.Eip")
	fake := &fakeEIPClient{current: boundEIP(), allocateErr: quota, fallbackErr: quota}
	srv, st := newReplaceIPServer(t, selfBoundEIPAccount(), fake)

	recorder := replaceIPFor(t, srv)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "没有公网 IP") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertCalls(t, fake, "describe,traffic 203.0.113.10,unassociate eip-old,describe,release eip-old,allocate,allocate default")
	// The old EIP is gone, so the account must say so for the retry to resume.
	assertAccountNetwork(t, st, "", "")
	assertOldIPQueuedForDNSCleanup(t, st)

	fake.calls, fake.allocateErr, fake.fallbackErr = nil, nil, nil
	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertCalls(t, fake, "allocate,associate eip-new")
	if fake.template.Bandwidth != 10 {
		t.Fatalf("retry lost the bandwidth: %#v", fake.template)
	}
	assertAccountNetwork(t, st, "eip-new", "198.51.100.20")
}

func TestReplaceIPReleasesNewEIPWhenBindingFails(t *testing.T) {
	fake := &fakeEIPClient{current: boundEIP(), associate: map[string]error{"eip-new": errors.New("IncorrectInstanceStatus")}}
	srv, st := newReplaceIPServer(t, selfBoundEIPAccount(), fake)

	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertCalls(t, fake, "describe,traffic 203.0.113.10,unassociate eip-old,describe,release eip-old,allocate,associate eip-new,release eip-new")
	assertAccountNetwork(t, st, "", "")
}

func TestReplaceIPRebindsOldEIPWhenReleaseFails(t *testing.T) {
	fake := &fakeEIPClient{current: boundEIP(), release: map[string]error{"eip-old": errors.New("IncorrectEipStatus")}}
	srv, st := newReplaceIPServer(t, selfBoundEIPAccount(), fake)

	recorder := replaceIPFor(t, srv)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "已重新绑定旧 EIP") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertCalls(t, fake, "describe,traffic 203.0.113.10,unassociate eip-old,describe,release eip-old,associate eip-old")
	assertAccountNetwork(t, st, "eip-old", "203.0.113.10")
	// The IP did not change, so its CMS total must not be counted twice.
	if sample, _ := st.InstanceTrafficUsage(1, "i-1", time.Now().Format("2006-01")); sample.RetiredBytes != 0 || sample.IPSinceMS != 0 {
		t.Fatalf("failed swap retired the unchanged IP: %+v", sample)
	}
}

func TestReplaceIPReleasesAlreadyUnboundOldEIP(t *testing.T) {
	eip := boundEIP()
	eip.InstanceID, eip.Status = "", "Available"
	fake := &fakeEIPClient{current: eip}
	srv, st := newReplaceIPServer(t, selfBoundEIPAccount(), fake)

	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertCalls(t, fake, "describe,traffic 203.0.113.10,describe,release eip-old,allocate,associate eip-new")
	assertAccountNetwork(t, st, "eip-new", "198.51.100.20")
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
			if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			assertCalls(t, fake, "describe")
			assertAccountNetwork(t, st, "eip-old", "203.0.113.10")
		})
	}
}

func TestReplaceIPRejectsInstanceWithoutEIP(t *testing.T) {
	account := selfBoundEIPAccount()
	account.PublicIPMode, account.EIPAllocationID, account.EIPAddress = "ecs_public_ip", "", ""
	fake := &fakeEIPClient{}
	srv, _ := newReplaceIPServer(t, account, fake)
	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusBadRequest || len(fake.calls) != 0 {
		t.Fatalf("status=%d calls=%v body=%s", recorder.Code, fake.calls, recorder.Body.String())
	}
}
