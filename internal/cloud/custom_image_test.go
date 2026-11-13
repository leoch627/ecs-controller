package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Vector from the official alibabacloud-oss-go-sdk-v2 signer tests.
func TestOSSV4SignatureMatchesSDKVector(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPut, "http://bucket.oss-cn-hangzhou.aliyuncs.com", nil)
	req.Header.Add("x-oss-head1", "value")
	req.Header.Add("abc", "value")
	req.Header.Add("ZAbc", "value")
	req.Header.Add("XYZ", "value")
	req.Header.Add("content-type", "text/plain")
	values := url.Values{}
	values.Add("param1", "value1")
	values.Add("+param1", "value3")
	values.Add("|param1", "value4")
	values.Add("+param2", "")
	values.Add("|param2", "")
	values.Add("param2", "")
	req.URL.RawQuery = values.Encode()

	client := &OSSClient{AccessKey: "ak", Secret: "sk", Region: "cn-hangzhou"}
	client.sign(req, "bucket", "1234+-/123/1.txt", time.Unix(1702743657, 0))

	want := "OSS4-HMAC-SHA256 Credential=ak/20231216/cn-hangzhou/oss/aliyun_v4_request,Signature=e21d18daa82167720f9b1047ae7e7f1ce7cb77a31e8203a7d5f4624fa0284afe"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("authorization = %s, want %s", got, want)
	}
}

func TestCustomImageName(t *testing.T) {
	cases := map[[2]string]string{
		{"", "https://example.com/dl/alpine-virt-3.20.qcow2?x=1"}: "alpine-virt-3.20",
		{"debian13-1g", ""}:                    "debian13-1g",
		{"", "https://example.com/3.20.raw"}:   "img-3.20",
		{"my image!", "https://example.com/a"}: "my-image",
	}
	for input, want := range cases {
		if got := CustomImageName(input[0], input[1]); got != want {
			t.Errorf("CustomImageName(%q, %q) = %q, want %q", input[0], input[1], got, want)
		}
	}
}

func TestEnsureCustomImageUploadsImportsAndCleansUp(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	var imported url.Values
	var uploaded string
	describeCount := 0
	record := func(call string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/alpine.qcow2":
			_, _ = w.Write([]byte("QFI\xfb-fake-qcow2-image"))
		case strings.HasPrefix(r.URL.Path, "/oss/"):
			if !strings.HasPrefix(r.Header.Get("Authorization"), "OSS4-HMAC-SHA256 Credential=ak/") {
				t.Errorf("unsigned OSS request: %s %s", r.Method, r.URL.Path)
			}
			record(r.Method + " " + strings.TrimPrefix(r.URL.Path, "/oss"))
			if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, ".qcow2") {
				body, _ := io.ReadAll(r.Body)
				uploaded = string(body)
			}
		default:
			action := r.URL.Query().Get("Action")
			record(action)
			response := map[string]any{}
			switch action {
			case "DescribeImages":
				mu.Lock()
				describeCount++
				n := describeCount
				mu.Unlock()
				switch n {
				case 1: // lookup by name: nothing yet
					response["Images"] = map[string]any{"Image": []any{}}
				case 2:
					response["Images"] = map[string]any{"Image": []any{map[string]any{"ImageId": "m-1", "Status": "Creating", "Progress": "40%"}}}
				default:
					response["Images"] = map[string]any{"Image": []any{map[string]any{"ImageId": "m-1", "Status": "Available"}}}
				}
			case "ImportImage":
				imported = r.URL.Query()
				response["ImageId"] = "m-1"
			}
			_ = json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	rpc := &RPCClient{HTTPClient: server.Client(), Endpoint: server.URL + "/rpc", Version: "2014-05-26", AccessKey: "ak", Secret: "sk"}
	service := &Service{ECS: rpc, RAM: rpc, ImageHTTP: server.Client(), ImagePollInterval: time.Millisecond,
		ImageOSS: &OSSClient{HTTPClient: server.Client(), AccessKey: "ak", Secret: "sk", Region: "cn-hongkong", Endpoint: server.URL + "/oss"}}

	var steps []string
	id, err := service.EnsureCustomImage(context.Background(), "cn-hongkong", CustomImageSpec{Name: "alpine-test", SourceURL: server.URL + "/alpine.qcow2", DiskSizeGB: 1}, func(step string) { steps = append(steps, step) })
	if err != nil {
		t.Fatal(err)
	}
	if id != "m-1" {
		t.Fatalf("image id = %q", id)
	}
	if uploaded != "QFI\xfb-fake-qcow2-image" {
		t.Fatalf("uploaded body = %q", uploaded)
	}
	bucket := imageBucketName("ak", "cn-hongkong")
	if imported.Get("DiskDeviceMapping.1.OSSBucket") != bucket || imported.Get("DiskDeviceMapping.1.OSSObject") != "alpine-test.qcow2" || imported.Get("DiskDeviceMapping.1.Format") != "QCOW2" || imported.Get("DiskDeviceMapping.1.DiskImageSize") != "1" || imported.Get("Platform") != "Others Linux" {
		t.Fatalf("unexpected ImportImage params: %v", imported)
	}
	joined := strings.Join(calls, "|")
	want := "DescribeImages|PUT /" + bucket + "/|PUT /" + bucket + "/alpine-test.qcow2|GetRole|ImportImage|DescribeImages|DescribeImages|DELETE /" + bucket + "/alpine-test.qcow2|DELETE /" + bucket + "/"
	if joined != want {
		t.Fatalf("calls = %s\nwant    %s", joined, want)
	}
	if len(steps) == 0 || !strings.Contains(strings.Join(steps, "|"), "等待镜像导入完成 40%") {
		t.Fatalf("progress steps = %v", steps)
	}
}

func TestEnsureCustomImageReusesAvailableImage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if action := r.URL.Query().Get("Action"); action != "DescribeImages" {
			t.Errorf("unexpected action %s", action)
		}
		// ImageName is a fuzzy filter: the near-miss must be ignored.
		_ = json.NewEncoder(w).Encode(map[string]any{"Images": map[string]any{"Image": []any{
			map[string]any{"ImageId": "m-other", "ImageName": "alpine-test-old", "Status": "Available"},
			map[string]any{"ImageId": "m-2", "ImageName": "alpine-test", "Status": "Available"},
		}}})
	}))
	defer server.Close()
	service := &Service{ECS: &RPCClient{HTTPClient: server.Client(), Endpoint: server.URL, Version: "2014-05-26", AccessKey: "ak", Secret: "sk"}}
	id, err := service.EnsureCustomImage(context.Background(), "cn-hongkong", CustomImageSpec{Name: "alpine-test"}, nil)
	if err != nil || id != "m-2" {
		t.Fatalf("id = %q, err = %v", id, err)
	}
}

func TestDeleteImportedImageRemovesImageAndSnapshotOnlyWhenImported(t *testing.T) {
	var calls []string
	description := importedImageMark
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		calls = append(calls, query.Get("Action")+" "+query.Get("ImageId")+query.Get("SnapshotId"))
		response := map[string]any{}
		if query.Get("Action") == "DescribeImages" {
			response["Images"] = map[string]any{"Image": []any{map[string]any{
				"ImageId": "m-1", "Status": "Available", "Description": description,
				"DiskDeviceMappings": map[string]any{"DiskDeviceMapping": []any{map[string]any{"SnapshotId": "s-1"}}},
			}}}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	service := &Service{ECS: &RPCClient{HTTPClient: server.Client(), Endpoint: server.URL, Version: "2014-05-26", AccessKey: "ak", Secret: "sk"}}

	deleted, err := service.DeleteImportedImage(context.Background(), "cn-hongkong", "m-1")
	if err != nil || !deleted {
		t.Fatalf("deleted = %v, err = %v", deleted, err)
	}
	if got := strings.Join(calls, "|"); got != "DescribeImages m-1|DeleteImage m-1|DeleteSnapshot s-1" {
		t.Fatalf("calls = %s", got)
	}

	// An image the user made themselves must be left untouched.
	calls, description = nil, "my own image"
	deleted, err = service.DeleteImportedImage(context.Background(), "cn-hongkong", "m-1")
	if err != nil || deleted {
		t.Fatalf("deleted = %v, err = %v", deleted, err)
	}
	if got := strings.Join(calls, "|"); got != "DescribeImages m-1" {
		t.Fatalf("calls = %s", got)
	}
}
