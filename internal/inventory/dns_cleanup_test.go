package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/store"
)

// flakyListClient omits an instance from the full list while the per-ID
// lookup still finds it, like a provider-side list inconsistency.
type flakyListClient struct {
	cloud.Client
	hidden cloud.Instance
}

func (f *flakyListClient) DescribeInstances(context.Context, string) ([]cloud.Instance, error) {
	return nil, nil
}

func (f *flakyListClient) DescribeInstance(context.Context, string, string) (*cloud.Instance, error) {
	copy := f.hidden
	return &copy, nil
}

func cleanupJobs(t *testing.T, st *store.Store) []store.JobRecord {
	t.Helper()
	jobs, err := st.ListJobs(store.DNSCleanupKind, 50)
	if err != nil {
		t.Fatal(err)
	}
	return jobs
}

func TestVanishedInstanceQueuesDNSCleanup(t *testing.T) {
	st, group := newInventoryStore(t)
	defer st.Close()
	_ = st.SetSetting("dns_cleanup_enabled", "1")
	if err := st.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: group.GroupKey, InstanceID: "i-gone", InstanceStatus: "Running", PublicIP: "47.1.1.1", Remark: "hk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncGroup(context.Background(), st, group, &fakeClient{}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	jobs := cleanupJobs(t, st)
	if len(jobs) != 1 || jobs[0].EntityKey != "47.1.1.1" || jobs[0].Status != "queued" {
		t.Fatalf("expected one queued cleanup for 47.1.1.1, got %+v", jobs)
	}
}

func TestFlakyListDoesNotQueueDNSCleanup(t *testing.T) {
	st, group := newInventoryStore(t)
	defer st.Close()
	_ = st.SetSetting("dns_cleanup_enabled", "1")
	if err := st.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: group.GroupKey, InstanceID: "i-still", InstanceStatus: "Running", PublicIP: "47.1.1.2"}); err != nil {
		t.Fatal(err)
	}
	client := &flakyListClient{hidden: cloud.Instance{ID: "i-still", Status: "Running", PublicIP: "47.1.1.2"}}
	if _, err := SyncGroup(context.Background(), st, group, client, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if jobs := cleanupJobs(t, st); len(jobs) != 0 {
		t.Fatalf("instance that still exists must not be cleaned: %+v", jobs)
	}
}

func TestCleanupSwitchedOffQueuesNothing(t *testing.T) {
	st, group := newInventoryStore(t)
	defer st.Close()
	if err := st.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: group.GroupKey, InstanceID: "i-gone", PublicIP: "47.1.1.3"}); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncGroup(context.Background(), st, group, &fakeClient{}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if jobs := cleanupJobs(t, st); len(jobs) != 0 {
		t.Fatalf("cleanup is off, got %+v", jobs)
	}
}

func TestExpiredPrepaidInstanceIsQueuedOnceAndRenewalRearms(t *testing.T) {
	st, group := newInventoryStore(t)
	defer st.Close()
	_ = st.SetSetting("dns_cleanup_enabled", "1")
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	instance := func(expires time.Time) cloud.Instance {
		return cloud.Instance{ID: "i-pre", Status: "Stopped", PublicIP: "47.1.1.4", ChargeType: "PrePaid", ExpiredTime: expires.UTC().Format("2006-01-02T15:04Z")}
	}
	sync := func(inst cloud.Instance, at time.Time) {
		t.Helper()
		if _, err := SyncGroup(context.Background(), st, group, &fakeClient{instances: []cloud.Instance{inst}}, at, nil); err != nil {
			t.Fatal(err)
		}
	}

	sync(instance(now.Add(48*time.Hour)), now)
	if jobs := cleanupJobs(t, st); len(jobs) != 0 {
		t.Fatalf("not expired yet, got %+v", jobs)
	}

	expired := instance(now.Add(-time.Hour))
	sync(expired, now)
	jobs := cleanupJobs(t, st)
	if len(jobs) != 1 || jobs[0].EntityKey != "47.1.1.4" {
		t.Fatalf("expired prepaid instance should be queued once, got %+v", jobs)
	}
	if err := st.FinishJob(jobs[0].JobID); err != nil {
		t.Fatal(err)
	}
	sync(expired, now.Add(time.Minute))
	if jobs := cleanupJobs(t, st); len(jobs) != 1 {
		t.Fatalf("an already-handled expiry must not be queued again, got %d jobs", len(jobs))
	}

	sync(instance(now.Add(30*24*time.Hour)), now.Add(2*time.Minute))
	if st.InstanceExpiry("i-pre").QueuedAt != 0 {
		t.Fatal("renewal should reset the queued marker")
	}
	sync(instance(now.Add(time.Minute)), now.Add(10*time.Minute))
	if jobs := cleanupJobs(t, st); len(jobs) != 2 {
		t.Fatalf("a later expiry should be queued again, got %d jobs", len(jobs))
	}
}

func TestPostPaidInstanceNeverCountsAsExpired(t *testing.T) {
	st, group := newInventoryStore(t)
	defer st.Close()
	_ = st.SetSetting("dns_cleanup_enabled", "1")
	inst := cloud.Instance{ID: "i-post", Status: "Running", PublicIP: "47.1.1.5", ChargeType: "PostPaid", ExpiredTime: "2000-01-01T00:00Z"}
	if _, err := SyncGroup(context.Background(), st, group, &fakeClient{instances: []cloud.Instance{inst}}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if jobs := cleanupJobs(t, st); len(jobs) != 0 {
		t.Fatalf("pay-as-you-go instances have no expiry, got %+v", jobs)
	}
}
