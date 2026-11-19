package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kori1c/ecs-controller/internal/app"
	"github.com/Kori1c/ecs-controller/internal/cloud"
	"github.com/Kori1c/ecs-controller/internal/store"
)

type fakeCustomPreflight struct{ fakePreflightClient }

func (f *fakeCustomPreflight) GetSystemDiskOptions(context.Context, string, string, string) ([]map[string]any, error) {
	return []map[string]any{
		{"value": "cloud_essd_entry", "label": "ESSD Entry", "min": 20, "max": 2048, "unit": "GB"},
		{"value": "cloud_essd", "label": "ESSD", "min": 20, "max": 2048, "unit": "GB"},
	}, nil
}
func (f *fakeCustomPreflight) FindCustomImage(context.Context, string, string) (string, string, error) {
	return "", "", nil
}
func (f *fakeCustomPreflight) EnsureCustomImage(context.Context, string, cloud.CustomImageSpec, func(string)) (string, error) {
	return "m-1", nil
}
func (f *fakeCustomPreflight) DeleteImportedImage(context.Context, string, string) (bool, error) {
	return true, nil
}

func TestPreviewDefaultsCustomImageToDebianOnOneGBESSD(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveGroups([]app.AccountGroup{{GroupKey: "group-1", AccessKeyID: "ak", AccessKeySecret: "sk", RegionID: "cn-test", Remark: "test"}}); err != nil {
		t.Fatal(err)
	}
	srv := New(st, t.TempDir(), "", "setup-token", nil)
	srv.CloudFactory = func(app.Account) cloud.Client { return &fakeCustomPreflight{} }
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp := postJSON(t, client, httpSrv.URL+"/index.php?action=setup", map[string]any{"admin_password": "correct horse battery staple"}, map[string]string{"X-Setup-Token": "setup-token"})
	csrf := resp.Header.Get("X-CSRF-Token")
	resp.Body.Close()
	resp = postJSON(t, client, httpSrv.URL+"/index.php?action=preview_ecs_create", map[string]any{
		"accountGroupKey": "group-1", "instanceType": "ecs.test", "osKey": "custom", "zoneId": "zone-a",
		"systemDiskCategory": "cloud_essd_entry", "systemDiskSize": 1, "publicIpMode": "ecs_public_ip", "clientCidrIp": "192.0.2.10/32",
	}, map[string]string{"X-CSRF-Token": csrf})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview status: %d body=%s", resp.StatusCode, body)
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	summary, _ := result["summary"].(map[string]any)
	disk, _ := summary["systemDisk"].(map[string]any)
	if disk["category"] != "cloud_essd" || disk["size"] != float64(1) {
		t.Fatalf("expected 1 GB ESSD, got %#v", disk)
	}
	if !strings.Contains(stringValue(summary["osLabel"]), cloud.DefaultImageName) || !strings.Contains(string(body), "ESSD Entry 系统盘最小 20 GB") {
		t.Fatalf("default image or disk warning missing: %s", body)
	}
}
