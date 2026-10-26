package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/store"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// cloudflareTokenChecker answers the zone list only for the expected token.
func cloudflareTokenChecker(token string, seen *[]string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		*seen = append(*seen, got)
		status, body := 200, map[string]any{"success": true, "result": []map[string]any{{"id": "zone-1", "name": "example.com"}}, "result_info": map[string]any{"total_pages": 1}}
		if got != token {
			status, body = 401, map[string]any{"success": false, "errors": []map[string]any{{"code": 9109, "message": "Invalid access token"}}}
		}
		if strings.Contains(r.URL.Path, "/dns_records") {
			body["result"] = []map[string]any{}
		}
		raw, _ := json.Marshal(body)
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}, nil
	})}
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	return body
}

func TestDNSConfigRoundTripMasksSecretsAndKeepsThemOnResave(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	save := func(ddns map[string]any) {
		t.Helper()
		if err := srv.saveConfig(map[string]any{"traffic_threshold": 95, "api_interval": 600, "Ddns": ddns}); err != nil {
			t.Fatal(err)
		}
	}
	save(map[string]any{
		"enabled": true, "cleanup_enabled": true, "provider": "huawei", "domain": "https://Example.COM/",
		"credentials": map[string]any{
			"huawei":     map[string]any{"ak": "HWAK", "sk": "hw-secret", "region": "ap-southeast-1", "zone_id": ""},
			"cloudflare": map[string]any{"token": "cf-secret", "proxied": true},
		},
	})
	settings := st.Settings()
	if settings["ddns_domain"] != "example.com" || settings["ddns_provider"] != "huawei" || settings["dns_cleanup_enabled"] != "1" {
		t.Fatalf("settings were not normalized: %#v", settings)
	}
	if !strings.HasPrefix(settings["ddns_hw_sk"], "ENC1") || !strings.HasPrefix(settings["ddns_cf_token"], "ENC1") {
		t.Fatalf("secrets must be sealed at rest: hw=%q cf=%q", settings["ddns_hw_sk"], settings["ddns_cf_token"])
	}

	config := srv.dnsConfig()
	credentials := config["credentials"].(map[string]any)
	huawei := credentials["huawei"].(map[string]any)
	cloudflare := credentials["cloudflare"].(map[string]any)
	if huawei["sk"] != "********" || huawei["ak"] != "HWAK" || cloudflare["token"] != "********" || cloudflare["proxied"] != true {
		t.Fatalf("config read-back: %#v", credentials)
	}
	if _, ok := credentials["godaddy"]; !ok {
		t.Fatal("every provider should be present so switching keeps the form shape")
	}

	// Saving the masked form back must not overwrite the stored secrets.
	save(map[string]any{"enabled": true, "cleanup_enabled": true, "provider": "huawei", "domain": "example.com", "credentials": credentials})
	reopened, _ := st.OpenSecret(st.GetSetting("ddns_hw_sk", ""))
	if reopened != "hw-secret" {
		t.Fatalf("masked resave replaced the secret with %q", reopened)
	}
}

func TestDNSConfigAcceptsLegacyCloudflarePayload(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	if err := srv.saveConfig(map[string]any{"traffic_threshold": 95, "api_interval": 600, "Ddns": map[string]any{
		"enabled": true, "provider": "cloudflare", "domain": "example.com", "cloudflare": map[string]any{"token": "legacy-token", "zone_id": "z1"},
	}}); err != nil {
		t.Fatal(err)
	}
	token, _ := st.OpenSecret(st.GetSetting("ddns_cf_token", ""))
	if token != "legacy-token" || st.GetSetting("ddns_cf_zone_id", "") != "z1" {
		t.Fatalf("legacy cloudflare settings were dropped: token=%q zone=%q", token, st.GetSetting("ddns_cf_zone_id", ""))
	}
}

func TestTestDNSUsesSavedSecretForMaskedDraft(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	var seen []string
	srv.DNSClient = cloudflareTokenChecker("saved-token", &seen)
	if err := srv.saveConfig(map[string]any{"traffic_threshold": 95, "api_interval": 600, "Ddns": map[string]any{
		"provider": "cloudflare", "domain": "example.com", "credentials": map[string]any{"cloudflare": map[string]any{"token": "saved-token"}},
	}}); err != nil {
		t.Fatal(err)
	}
	draft := func(token string) map[string]any {
		return map[string]any{"Ddns": map[string]any{"provider": "cloudflare", "domain": "example.com", "credentials": map[string]any{"cloudflare": map[string]any{"token": token}}}}
	}

	recorder := httptest.NewRecorder()
	srv.testDNS(recorder, draft("********"))
	if body := decodeBody(t, recorder); body["success"] != true {
		t.Fatalf("masked draft should test with the saved token: %#v (sent %v)", body, seen)
	}
	recorder = httptest.NewRecorder()
	srv.testDNS(recorder, draft("typed-but-wrong"))
	body := decodeBody(t, recorder)
	if body["success"] != false || !strings.Contains(body["message"].(string), "凭据不正确或已失效") {
		t.Fatalf("a newly typed token should be tested as typed: %#v", body)
	}
	if st.GetSetting("ddns_cf_token", "") == "" {
		t.Fatal("testing must not clear the saved token")
	}
}

func TestDNSCleanupHistoryAndRetryRequireCSRF(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	templatePath := filepath.Join(t.TempDir(), "template.html")
	if err := os.WriteFile(templatePath, []byte("<!doctype html>ok"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := New(st, t.TempDir(), templatePath, "setup-token", nil)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp := postJSON(t, client, httpSrv.URL+"/index.php?action=setup", map[string]any{"admin_password": "correct horse battery staple", "traffic_threshold": 95}, map[string]string{"X-Setup-Token": "setup-token"})
	csrf := resp.Header.Get("X-CSRF-Token")
	resp.Body.Close()

	_ = st.SetSetting("dns_cleanup_enabled", "1")
	if _, err := st.EnqueueDNSCleanup("47.1.1.1", "i-old", "hk", "expired"); err != nil {
		t.Fatal(err)
	}
	job, _ := st.ClaimJob(time.Minute)
	_ = st.FailJob(job.JobID, "Cloudflare 凭据不正确或已失效。")

	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=get_dns_cleanup_tasks", map[string]any{}, nil)
	var list struct {
		Success bool             `json:"success"`
		Data    []map[string]any `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if !list.Success || len(list.Data) != 1 || list.Data[0]["status"] != "failed" || list.Data[0]["ip"] != "47.1.1.1" || list.Data[0]["reasonText"] != "包年包月实例已到期" {
		t.Fatalf("cleanup history: %#v", list)
	}

	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=retry_dns_cleanup", map[string]any{"id": job.JobID}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("retry without csrf status: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=retry_dns_cleanup", map[string]any{"id": job.JobID}, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("retry status: %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()
	record, _ := st.JobRecordByID(job.JobID)
	if record.Status != "queued" || record.Attempts != 0 || record.LastError != "" {
		t.Fatalf("retry should requeue from scratch: %#v", record)
	}
	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=retry_dns_cleanup", map[string]any{"id": job.JobID}, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("retrying a queued job twice status: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRefreshMissingInstanceQueuesDNSCleanup(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SetSetting("dns_cleanup_enabled", "1")
	if err := st.UpsertAccount(app.Account{AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", GroupKey: "group-1", InstanceID: "i-missing", InstanceStatus: "Running", PublicIP: "47.1.1.9"}); err != nil {
		t.Fatal(err)
	}
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	srv.CloudFactory = func(app.Account) cloud.Client { return &fakeMissingInstanceClient{} }
	srv.refreshAccount(httptest.NewRecorder(), map[string]any{"accountId": 1})
	jobs, _ := st.ListJobs(store.DNSCleanupKind, 10)
	if len(jobs) != 1 || jobs[0].EntityKey != "47.1.1.9" || !strings.Contains(jobs[0].Payload, `"vanished"`) {
		t.Fatalf("a vanished instance's IP should be queued: %#v", jobs)
	}
}
