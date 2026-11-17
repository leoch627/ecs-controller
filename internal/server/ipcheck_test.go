package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/reach"
	"github.com/Kori1c/ecs-controller/internal/store"
)

// sequenceEIPClient hands out one address per allocation, in order.
type sequenceEIPClient struct {
	cloud.Client
	mu        sync.Mutex
	addresses []string
	issued    map[string]string // allocation ID -> address
	attached  map[string]bool
	calls     []string
}

func (f *sequenceEIPClient) record(call string) {
	f.calls = append(f.calls, call)
}

func (f *sequenceEIPClient) DescribeEIP(_ context.Context, _ string, allocationID string) (*cloud.EIPDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	address, ok := f.issued[allocationID]
	if !ok {
		return nil, &cloud.APIError{Provider: "aws", Code: "NotFoundException", HTTPStatus: 400}
	}
	detail := &cloud.EIPDetail{AllocationID: allocationID, Address: address, Status: "Available", ChargeType: "PostPaid"}
	if f.attached[allocationID] {
		detail.Status, detail.InstanceID = "InUse", "i-1"
	}
	return detail, nil
}

func (f *sequenceEIPClient) AllocateEIPLike(context.Context, string, cloud.EIPDetail) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.addresses) == 0 {
		return "", "", fmt.Errorf("no more addresses")
	}
	address := f.addresses[0]
	f.addresses = f.addresses[1:]
	allocationID := fmt.Sprintf("ip-%d", len(f.issued)+1)
	if f.issued == nil {
		f.issued, f.attached = map[string]string{}, map[string]bool{}
	}
	f.issued[allocationID] = address
	f.record("allocate " + address)
	return allocationID, address, nil
}

func (f *sequenceEIPClient) AssociateEIP(_ context.Context, _ string, allocationID, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attached[allocationID] = true
	f.record("associate " + allocationID)
	return nil
}

func (f *sequenceEIPClient) UnassociateEIP(_ context.Context, _ string, allocationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attached[allocationID] = false
	f.record("unassociate " + allocationID)
	return nil
}

func (f *sequenceEIPClient) ReleaseEIP(_ context.Context, _ string, allocationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.issued, allocationID)
	f.record("release " + allocationID)
	return nil
}

func (f *sequenceEIPClient) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

// ipCheckFixture configures a probe that cannot reach the blocked addresses
// and a panel that cannot reach the dead ones.
func ipCheckFixture(t *testing.T, st *store.Store, maxSwaps int, blocked, dead []string) {
	t.Helper()
	contains := func(list []string, ip string) bool {
		for _, item := range list {
			if item == ip {
				return true
			}
		}
		return false
	}
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req reach.CheckRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Port != 443 {
			t.Errorf("probe asked for port %d, want 443", req.Port)
		}
		_ = json.NewEncoder(w).Encode(reach.CheckResponse{Reachable: !contains(blocked, req.IP) && !contains(dead, req.IP), LatencyMS: 80})
	}))
	t.Cleanup(probe.Close)
	token, err := st.Seal("0123456789abcdef-token")
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"ipcheck_probe_url": probe.URL, "ipcheck_probe_token": token, "ipcheck_port": "443", "ipcheck_max_swaps": fmt.Sprint(maxSwaps)} {
		if err := st.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	settle, manual, confirm, retry, dial := ipCheckSettle, ipCheckManualSettle, ipCheckConfirmDelay, ipCheckRetryPause, localDial
	ipCheckSettle, ipCheckManualSettle, ipCheckConfirmDelay, ipCheckRetryPause = 5*time.Millisecond, 5*time.Millisecond, time.Millisecond, time.Millisecond
	localDial = func(_ context.Context, req reach.CheckRequest) reach.CheckResponse {
		return reach.CheckResponse{Reachable: !contains(dead, req.IP)}
	}
	t.Cleanup(func() {
		ipCheckSettle, ipCheckManualSettle, ipCheckConfirmDelay, ipCheckRetryPause, localDial = settle, manual, confirm, retry, dial
	})
}

func lightsailAccount() app.Account {
	return app.Account{ID: 1, AccessKeyID: "AKIATEST", AccessKeySecret: "sk", RegionID: "ap-northeast-1", SiteType: cloud.SiteAWS, InstanceID: "i-1", InstanceName: "jp-1", InstanceStatus: "Running", PublicIP: "203.0.113.10", PublicIPMode: "ecs_public_ip"}
}

func waitForSwap(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, busy := srv.ipReplacing.Load(int64(1)); !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("IP replacement did not finish")
}

func TestReplaceIPSwapsAgainWhileNewIPIsBlocked(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)
	ipCheckFixture(t, st, 5, []string{"198.51.100.1", "198.51.100.2"}, nil)

	recorder := replaceIPFor(t, srv)
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"queued":true`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	waitForSwap(t, srv)

	want := "allocate 198.51.100.1,associate ip-1," +
		"unassociate ip-1,release ip-1,allocate 198.51.100.2,associate ip-1," +
		"unassociate ip-1,release ip-1,allocate 198.51.100.3,associate ip-1"
	if got := fake.joined(); got != want {
		t.Fatalf("calls=%s\nwant=%s", got, want)
	}
	assertAccountNetwork(t, st, "ip-1", "198.51.100.3")
	check := st.IPChecks()[1]
	if check.IP != "198.51.100.3" || check.Status != ipCheckOK {
		t.Fatalf("check=%+v", check)
	}
}

func TestReplaceIPStopsWhenBlockingCannotBeDetermined(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1", "198.51.100.2"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)
	// Nobody reaches the new IP: the port is closed, which is not a block.
	ipCheckFixture(t, st, 5, nil, []string{"198.51.100.1"})

	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	waitForSwap(t, srv)

	if got := fake.joined(); got != "allocate 198.51.100.1,associate ip-1" {
		t.Fatalf("an undetermined result must not trigger another swap: %s", got)
	}
	if check := st.IPChecks()[1]; check.IP != "198.51.100.1" || check.Status != ipCheckUnknown {
		t.Fatalf("check=%+v", check)
	}
}

func TestReplaceIPGivesUpAfterMaxSwaps(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)
	ipCheckFixture(t, st, 2, []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}, nil)

	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	waitForSwap(t, srv)

	if got := strings.Count(fake.joined(), "allocate"); got != 2 {
		t.Fatalf("allocations=%d, want 2: %s", got, fake.joined())
	}
	assertAccountNetwork(t, st, "ip-1", "198.51.100.2")
	if check := st.IPChecks()[1]; check.IP != "198.51.100.2" || check.Status != ipCheckBlocked {
		t.Fatalf("check=%+v", check)
	}
}

func TestReplaceIPAttachesFirstStaticIPToLightsailInstance(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)

	// Without a probe the swap is synchronous and runs once.
	recorder := replaceIPFor(t, srv)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := fake.joined(); got != "allocate 198.51.100.1,associate ip-1" {
		t.Fatalf("calls=%s", got)
	}
	account := assertAccountNetwork(t, st, "ip-1", "198.51.100.1")
	if !account.EIPManaged {
		t.Fatalf("the new static IP should be managed: %+v", account)
	}
	// The dynamic address went back to AWS.
	assertOldIPQueuedForDNSCleanup(t, st)
}

func TestReplaceIPStillRequiresEIPOnAlibabaCloud(t *testing.T) {
	account := lightsailAccount()
	account.SiteType = "international"
	srv, _ := newReplaceIPServer(t, account, &sequenceEIPClient{})
	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCheckInstanceIPReportsBlockedAndStatusHidesStaleResults(t *testing.T) {
	srv, st := newReplaceIPServer(t, lightsailAccount(), &sequenceEIPClient{})
	ipCheckFixture(t, st, 5, []string{"203.0.113.10"}, nil)

	recorder := httptest.NewRecorder()
	srv.checkInstanceIP(recorder, map[string]any{"accountId": 1})
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"blocked"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	statusOf := func() map[string]any {
		recorder := httptest.NewRecorder()
		srv.status(recorder)
		var body struct {
			Enabled bool             `json:"ip_check_enabled"`
			Data    []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || len(body.Data) != 1 || !body.Enabled {
			t.Fatalf("status body=%s err=%v", recorder.Body.String(), err)
		}
		return body.Data[0]
	}
	item := statusOf()
	if check, _ := item["ipCheck"].(map[string]any); check["status"] != "blocked" || item["siteType"] != cloud.SiteAWS || item["ipReplacing"] != false {
		t.Fatalf("item=%v", item)
	}
	// Once the instance has another IP the old verdict no longer applies.
	if err := st.UpdateNetwork(1, map[string]any{"public_ip": "198.51.100.9"}); err != nil {
		t.Fatal(err)
	}
	if _, stale := statusOf()["ipCheck"]; stale {
		t.Fatal("a result for a previous IP must not be shown")
	}
}

func TestSaveIPCheckConfigValidatesAndMasksToken(t *testing.T) {
	srv, st := newReplaceIPServer(t, lightsailAccount(), &sequenceEIPClient{})
	for name, data := range map[string]map[string]any{
		"bad url":     {"probe_url": "ftp://x", "probe_token": "0123456789abcdef", "port": 22, "max_swaps": 5},
		"short token": {"probe_url": "http://192.0.2.1:8433", "probe_token": "short", "port": 22, "max_swaps": 5},
		"bad port":    {"probe_url": "http://192.0.2.1:8433", "probe_token": "0123456789abcdef", "port": 0, "max_swaps": 5},
		"too many":    {"probe_url": "http://192.0.2.1:8433", "probe_token": "0123456789abcdef", "port": 22, "max_swaps": 50},
	} {
		if err := srv.saveIPCheckConfig(data); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
	if err := srv.saveIPCheckConfig(map[string]any{"probe_url": "http://192.0.2.1:8433/", "probe_token": "0123456789abcdef", "port": 443, "max_swaps": 3}); err != nil {
		t.Fatal(err)
	}
	// Saving the masked value keeps the stored token.
	if err := srv.saveIPCheckConfig(map[string]any{"probe_url": "http://192.0.2.1:8433", "probe_token": "********", "port": 443, "max_swaps": 3}); err != nil {
		t.Fatal(err)
	}
	cfg := srv.ipCheckSettings()
	if !cfg.enabled() || cfg.ProbeURL != "http://192.0.2.1:8433" || cfg.Token != "0123456789abcdef" || cfg.Port != 443 || cfg.MaxSwaps != 3 {
		t.Fatalf("settings=%+v", cfg)
	}
	if strings.Contains(st.GetSetting("ipcheck_probe_token", ""), "0123456789abcdef") {
		t.Fatal("the token must be stored encrypted")
	}
	if public := srv.ipCheckConfig(); public["probe_token"] != "********" {
		t.Fatalf("config exposes the token: %v", public)
	}
}

// attachedEIPClient also reports what the cloud says is attached right now.
type attachedEIPClient struct {
	*sequenceEIPClient
}

func (f attachedEIPClient) DescribeInstancePublicNetworks(context.Context, string, []string) (map[string]cloud.InstancePublicNetwork, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	networks := map[string]cloud.InstancePublicNetwork{}
	for allocationID, address := range f.issued {
		if f.attached[allocationID] {
			networks["i-1"] = cloud.InstancePublicNetwork{AllocationID: allocationID, Address: address}
		}
	}
	return networks, nil
}

func TestReplaceIPReleasesTheAddressTheCloudReportsAttached(t *testing.T) {
	fake := &sequenceEIPClient{
		addresses: []string{"198.51.100.2"},
		issued:    map[string]string{"ip-live": "198.51.100.1"},
		attached:  map[string]bool{"ip-live": true},
	}
	// The local row still names a static IP that was released long ago.
	account := lightsailAccount()
	account.PublicIPMode, account.EIPAllocationID, account.EIPAddress = "eip", "ip-stale", "203.0.113.10"
	srv, st := newReplaceIPServer(t, account, attachedEIPClient{fake})

	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := fake.joined(); got != "unassociate ip-live,release ip-live,allocate 198.51.100.2,associate ip-1" {
		t.Fatalf("calls=%s", got)
	}
	assertAccountNetwork(t, st, "ip-1", "198.51.100.2")
}

func TestReplaceIPSyncsDNSAfterEverySwap(t *testing.T) {
	fake := &sequenceEIPClient{addresses: []string{"198.51.100.1", "198.51.100.2"}}
	srv, st := newReplaceIPServer(t, lightsailAccount(), fake)
	ipCheckFixture(t, st, 5, []string{"198.51.100.1"}, nil)
	synced := make(chan string, 4)
	srv.SyncDNS = func(_ context.Context, accountID int64) {
		account, err := st.Account(accountID, false)
		if err != nil {
			t.Error(err)
			return
		}
		synced <- account.PublicIP
	}

	if recorder := replaceIPFor(t, srv); recorder.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	waitForSwap(t, srv)
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case ip := <-synced:
			seen[ip] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("DNS synced for %v, want both swaps", seen)
		}
	}
	if !seen["198.51.100.2"] {
		t.Fatalf("DNS never pointed at the final IP: %v", seen)
	}
}
