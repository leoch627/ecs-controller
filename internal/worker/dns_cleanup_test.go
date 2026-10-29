package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/store"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// fakeCloudflare is just enough of the Cloudflare v4 API for cleanup jobs.
type fakeCloudflare struct {
	mu      sync.Mutex
	records map[string]string // record id -> "name ip"
	deleted []string
	created int
	fail    bool
}

func (f *fakeCloudflare) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		reply := func(status int, result any) (*http.Response, error) {
			body, _ := json.Marshal(map[string]any{"success": status < 300, "result": result, "result_info": map[string]any{"total_pages": 1},
				"errors": []map[string]any{{"code": 9109, "message": "Invalid access token"}}})
			return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
		}
		if f.fail {
			return reply(401, nil)
		}
		path := strings.TrimPrefix(r.URL.Path, "/client/v4")
		switch {
		case r.Method == http.MethodGet && path == "/zones":
			return reply(200, []map[string]any{{"id": "zone-1", "name": "example.com"}})
		case r.Method == http.MethodGet && path == "/zones/zone-1/dns_records":
			items := []map[string]any{}
			for id, row := range f.records {
				name, ip, _ := strings.Cut(row, " ")
				if want := r.URL.Query().Get("content"); want != "" && want != ip {
					continue
				}
				items = append(items, map[string]any{"id": id, "name": name, "content": ip, "ttl": 1})
			}
			return reply(200, items)
		case r.Method == http.MethodPost && path == "/zones/zone-1/dns_records":
			var record struct{ Name, Content string }
			_ = json.NewDecoder(r.Body).Decode(&record)
			f.created++
			id := fmt.Sprintf("new-%d", f.created)
			f.records[id] = record.Name + " " + record.Content
			return reply(200, map[string]any{"id": id})
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/zones/zone-1/dns_records/"):
			id := strings.TrimPrefix(path, "/zones/zone-1/dns_records/")
			delete(f.records, id)
			f.deleted = append(f.deleted, id)
			return reply(200, map[string]any{"id": id})
		}
		return reply(404, nil)
	})}
}

func newCleanupWorker(t *testing.T, cf *fakeCloudflare) (*Worker, *store.Store) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	token, _ := s.Seal("cf-test-token")
	for key, value := range map[string]string{"dns_cleanup_enabled": "1", "ddns_provider": "cloudflare", "ddns_domain": "example.com", "ddns_cf_token": token} {
		if err := s.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	return &Worker{Store: s, DNSClient: cf.client()}, s
}

func runCleanup(t *testing.T, w *Worker, s *store.Store, ip string) (store.JobRecord, error) {
	t.Helper()
	if queued, err := s.EnqueueDNSCleanup(ip, "i-old", "hk", "expired"); err != nil || !queued {
		t.Fatalf("enqueue: %v %v", queued, err)
	}
	job, err := s.ClaimJob(2 * time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: %v %v", job, err)
	}
	runErr := w.execute(context.Background(), job)
	if runErr == nil {
		_ = s.FinishJob(job.JobID)
	}
	record, err := s.JobRecordByID(job.JobID)
	if err != nil {
		t.Fatal(err)
	}
	return *record, runErr
}

func cleanupOutcome(t *testing.T, job store.JobRecord) DNSCleanupResult {
	t.Helper()
	var result DNSCleanupResult
	if err := json.Unmarshal([]byte(job.Result), &result); err != nil {
		t.Fatalf("result %q: %v", job.Result, err)
	}
	return result
}

func TestDNSCleanupJobDeletesRecordsOfDeadIP(t *testing.T) {
	cf := &fakeCloudflare{records: map[string]string{"r1": "hk.example.com 47.1.1.1", "r2": "www.example.com 47.1.1.1", "r3": "jp.example.com 47.1.1.10"}}
	w, s := newCleanupWorker(t, cf)
	job, err := runCleanup(t, w, s, "47.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.deleted) != 2 || cf.records["r3"] == "" {
		t.Fatalf("only the dead IP's records should go, deleted %v, left %v", cf.deleted, cf.records)
	}
	result := cleanupOutcome(t, job)
	if result.Outcome != "done" || len(result.Changes) != 2 {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestDNSCleanupJobSkipsIPStillUsedByLiveInstance(t *testing.T) {
	cf := &fakeCloudflare{records: map[string]string{"r1": "hk.example.com 47.1.1.1"}}
	w, s := newCleanupWorker(t, cf)
	if err := s.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: "g", InstanceID: "i-new", InstanceStatus: "Running", PublicIP: "47.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	job, err := runCleanup(t, w, s, "47.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.deleted) != 0 {
		t.Fatalf("an IP in use must stay in DNS, deleted %v", cf.deleted)
	}
	if result := cleanupOutcome(t, job); result.Outcome != "skipped" || !strings.Contains(result.Message, "i-new") {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestDNSCleanupJobIgnoresExpiredOwnerOfIP(t *testing.T) {
	cf := &fakeCloudflare{records: map[string]string{"r1": "hk.example.com 47.1.1.1"}}
	w, s := newCleanupWorker(t, cf)
	if err := s.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: "g", InstanceID: "i-old", InstanceStatus: "Stopped", PublicIP: "47.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveInstanceExpiry(store.InstanceExpiry{InstanceID: "i-old", ChargeType: "PrePaid", ExpiredAt: time.Now().Add(-time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err := runCleanup(t, w, s, "47.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if len(cf.deleted) != 1 {
		t.Fatalf("the expired instance still listed must not block cleanup, deleted %v", cf.deleted)
	}
}

func TestDNSCleanupJobSwitchedOffIsSkipped(t *testing.T) {
	cf := &fakeCloudflare{records: map[string]string{"r1": "hk.example.com 47.1.1.1"}}
	w, s := newCleanupWorker(t, cf)
	if _, err := s.EnqueueDNSCleanup("47.1.1.1", "i-old", "hk", "expired"); err != nil {
		t.Fatal(err)
	}
	_ = s.SetSetting("dns_cleanup_enabled", "0")
	job, _ := s.ClaimJob(2 * time.Minute)
	if err := w.execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	record, _ := s.JobRecordByID(job.JobID)
	if result := cleanupOutcome(t, *record); result.Outcome != "skipped" || len(cf.deleted) != 0 {
		t.Fatalf("switched-off cleanup must not touch DNS: %+v %v", result, cf.deleted)
	}
}

func TestDNSCleanupJobReturnsProviderErrorForRetry(t *testing.T) {
	cf := &fakeCloudflare{records: map[string]string{"r1": "hk.example.com 47.1.1.1"}, fail: true}
	w, s := newCleanupWorker(t, cf)
	_, err := runCleanup(t, w, s, "47.1.1.1")
	if err == nil || !strings.Contains(err.Error(), "凭据不正确或已失效") {
		t.Fatalf("expected a credential error to retry, got %v", err)
	}
}

func TestReleasingInstanceQueuesDNSCleanup(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.SetSetting("dns_cleanup_enabled", "1")
	if err := s.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: "g", InstanceID: "i-delete", InstanceStatus: "Stopped", PublicIP: "47.1.1.7"}); err != nil {
		t.Fatal(err)
	}
	accounts, _ := s.LoadAccounts(false)
	id := accounts[0].ID
	if err := s.EnqueueJob("delete-job", "delete_instance", fmt.Sprint(id), map[string]any{"accountId": id}); err != nil {
		t.Fatal(err)
	}
	job, _ := s.ClaimJob(2 * time.Minute)
	if err := (&Worker{Store: s, Cloud: &fakeCloud{}}).execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	jobs, _ := s.ListJobs(store.DNSCleanupKind, 10)
	if len(jobs) != 1 || jobs[0].EntityKey != "47.1.1.7" || !strings.Contains(jobs[0].Payload, `"released"`) {
		t.Fatalf("release should queue the IP for cleanup, got %+v", jobs)
	}
}
