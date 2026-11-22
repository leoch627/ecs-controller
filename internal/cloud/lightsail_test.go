package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAWSV4AuthorizationMatchesAWSTestSuite uses the "get-vanilla" case of
// the AWS Signature Version 4 test suite.
func TestAWSV4AuthorizationMatchesAWSTestSuite(t *testing.T) {
	got := awsV4Authorization("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service", "GET", "/", "",
		map[string]string{"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"}, nil, "20150830T123600Z")
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got != want {
		t.Fatalf("authorization=%s\nwant=%s", got, want)
	}
}

type lightsailCall struct {
	action string
	input  map[string]any
}

// fakeLightsail answers each action from handlers and records the calls.
func fakeLightsail(t *testing.T, handlers map[string]func(input map[string]any) (int, string)) (*Lightsail, *[]lightsailCall) {
	t.Helper()
	calls := &[]lightsailCall{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), lightsailTargetPrefix)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-amz-json-1.1" || r.Host != "lightsail.ap-northeast-1.amazonaws.com" {
			t.Errorf("unexpected request: %s host=%s content-type=%s", r.Method, r.Host, r.Header.Get("Content-Type"))
		}
		if auth := r.Header.Get("Authorization"); !strings.Contains(auth, "Credential=AKIATEST/") || !strings.Contains(auth, "/ap-northeast-1/lightsail/aws4_request") || !strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-date;x-amz-target") {
			t.Errorf("authorization=%s", auth)
		}
		raw, _ := io.ReadAll(r.Body)
		input := map[string]any{}
		_ = json.Unmarshal(raw, &input)
		*calls = append(*calls, lightsailCall{action: action, input: input})
		handler := handlers[action]
		if handler == nil {
			t.Errorf("unexpected action %s", action)
			w.WriteHeader(500)
			return
		}
		status, body := handler(input)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	client := NewLightsail("AKIATEST", "secret", "ap-northeast-1")
	client.Endpoint, client.StaticIPPoll = server.URL, time.Millisecond
	return client, calls
}

func TestLightsailDescribeInstancesPagesAndMapsFields(t *testing.T) {
	client, calls := fakeLightsail(t, map[string]func(map[string]any) (int, string){
		"GetInstances": func(input map[string]any) (int, string) {
			if input["pageToken"] == "next" {
				return 200, `{"instances":[{"name":"jp-2","state":{"name":"stopped"},"bundleId":"micro_3_0"}]}`
			}
			return 200, `{"instances":[{"name":"jp-1","blueprintName":"Debian","bundleId":"nano_3_0","publicIpAddress":"198.51.100.7","privateIpAddress":"172.26.0.5","hardware":{"cpuCount":2,"ramSizeInGb":0.5},"state":{"name":"running"}}],"nextPageToken":"next"}`
		},
	})
	instances, err := client.DescribeInstances(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 2 || len(*calls) != 2 {
		t.Fatalf("instances=%+v calls=%d", instances, len(*calls))
	}
	first := instances[0]
	if first.ID != "jp-1" || first.Status != "Running" || first.PublicIP != "198.51.100.7" || first.PrivateIP != "172.26.0.5" || first.CPU != 2 || first.Memory != 512 || first.InstanceType != "nano_3_0" || first.OSName != "Debian" {
		t.Fatalf("first=%+v", first)
	}
	if instances[1].Status != "Stopped" {
		t.Fatalf("second=%+v", instances[1])
	}
}

func TestLightsailErrorsMapToNotFoundAndCredential(t *testing.T) {
	client, _ := fakeLightsail(t, map[string]func(map[string]any) (int, string){
		"GetInstance": func(map[string]any) (int, string) {
			return 400, `{"__type":"NotFoundException","code":"NotFoundException","message":"The Instance does not exist: gone"}`
		},
		"GetInstances": func(map[string]any) (int, string) {
			return 400, `{"__type":"com.amazon.coral.service#UnrecognizedClientException","message":"The security token included in the request is invalid."}`
		},
	})
	_, err := client.DescribeInstance(context.Background(), "", "gone")
	if !IsNotFound(err) || IsCredentialError(err) {
		t.Fatalf("GetInstance error=%v", err)
	}
	_, err = client.DescribeInstances(context.Background(), "")
	if !IsCredentialError(err) || IsNotFound(err) || !strings.HasPrefix(err.Error(), "aws UnrecognizedClientException") {
		t.Fatalf("GetInstances error=%v", err)
	}
}

func TestLightsailStaticIPLifecycle(t *testing.T) {
	polls := 0
	client, calls := fakeLightsail(t, map[string]func(map[string]any) (int, string){
		"AllocateStaticIp": func(map[string]any) (int, string) { return 200, `{"operations":[]}` },
		"GetStaticIp": func(input map[string]any) (int, string) {
			polls++
			if polls == 1 {
				return 200, `{"staticIp":{"name":"` + input["staticIpName"].(string) + `"}}`
			}
			return 200, `{"staticIp":{"name":"` + input["staticIpName"].(string) + `","ipAddress":"203.0.113.9","isAttached":false}}`
		},
		"AttachStaticIp":  func(map[string]any) (int, string) { return 200, `{}` },
		"DetachStaticIp":  func(map[string]any) (int, string) { return 200, `{}` },
		"ReleaseStaticIp": func(map[string]any) (int, string) { return 200, `{}` },
		"GetStaticIps": func(map[string]any) (int, string) {
			return 200, `{"staticIps":[{"name":"ip-a","ipAddress":"203.0.113.1","attachedTo":"jp-1","isAttached":true},{"name":"ip-b","ipAddress":"203.0.113.2","isAttached":false}]}`
		},
	})
	ctx := context.Background()
	name, ip, err := client.AllocateEIP(ctx, "")
	if err != nil || ip != "203.0.113.9" || !strings.HasPrefix(name, "ecs-controller-") {
		t.Fatalf("allocate name=%q ip=%q err=%v", name, ip, err)
	}
	if err := client.AssociateEIP(ctx, "", name, "jp-1"); err != nil {
		t.Fatal(err)
	}
	if err := client.UnassociateEIP(ctx, "", name); err != nil {
		t.Fatal(err)
	}
	if err := client.ReleaseEIP(ctx, "", name); err != nil {
		t.Fatal(err)
	}
	attach := (*calls)[3]
	if attach.action != "AttachStaticIp" || attach.input["staticIpName"] != name || attach.input["instanceName"] != "jp-1" {
		t.Fatalf("attach call=%+v", attach)
	}
	networks, err := client.DescribeInstancePublicNetworks(ctx, "", []string{"jp-1", "jp-2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 1 || networks["jp-1"].AllocationID != "ip-a" || networks["jp-1"].Address != "203.0.113.1" {
		t.Fatalf("networks=%+v", networks)
	}
	detail, err := client.DescribeEIP(ctx, "", "ip-x")
	if err != nil || detail.Status != "Available" || detail.InstanceID != "" {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
}

func TestLightsailTrafficSumsBothDirections(t *testing.T) {
	client, calls := fakeLightsail(t, map[string]func(map[string]any) (int, string){
		"GetInstanceMetricData": func(input map[string]any) (int, string) {
			if input["metricName"] == "NetworkOut" {
				return 200, `{"metricData":[{"sum":1000,"timestamp":1700000000},{"sum":500,"timestamp":1700003600}]}`
			}
			return 200, `{"metricData":[{"sum":250,"timestamp":1700000000}]}`
		},
	})
	bytes, points, err := client.GetInstanceMonthlyTraffic(context.Background(), "", "jp-1", "", 1699999000000, 1700007200000)
	if err != nil || bytes != 1750 || points != 2 {
		t.Fatalf("bytes=%v points=%d err=%v", bytes, points, err)
	}
	first := (*calls)[0].input
	if first["instanceName"] != "jp-1" || first["period"] != float64(3600) || first["startTime"] != float64(1699999000) || first["endTime"] != float64(1700007200) || first["unit"] != "Bytes" {
		t.Fatalf("metric request=%+v", first)
	}
}

func TestNewClientPicksBackendBySiteType(t *testing.T) {
	if _, ok := NewClient("ak", "sk", "ap-northeast-1", SiteAWS).(*Lightsail); !ok {
		t.Fatal("aws site type should use Lightsail")
	}
	if _, ok := NewClient("ak", "sk", "cn-hongkong", "international").(*Service); !ok {
		t.Fatal("other site types should use Alibaba Cloud")
	}
	var client Client = NewLightsail("ak", "sk", "ap-northeast-1")
	if _, ok := client.(EIPDetailClient); !ok {
		t.Fatal("Lightsail must support EIP details for IP replacement")
	}
	if _, ok := client.(InstancePublicNetworkClient); !ok {
		t.Fatal("Lightsail must report attached static IPs")
	}
	if _, ok := client.(AccountTester); !ok {
		t.Fatal("Lightsail must support the account test")
	}
}

func TestProtectionThresholdRunsAWSToFullAllowance(t *testing.T) {
	if got := ProtectionThreshold(SiteAWS, 95); got != 100 {
		t.Fatalf("AWS threshold=%v, want 100", got)
	}
	if got := ProtectionThreshold("international", 95); got != 95 {
		t.Fatalf("Alibaba Cloud threshold=%v, want configured 95", got)
	}
}
