package cloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SiteAWS marks an account group that manages AWS Lightsail instead of
// Alibaba Cloud ECS. It shares the site_type column with china/international.
const SiteAWS = "aws"

// ProtectionThreshold is the usage percent at which traffic protection acts.
// Lightsail overage is cheap, so AWS instances run to the full allowance and
// the configured threshold applies only to Alibaba Cloud.
func ProtectionThreshold(siteType string, configured float64) float64 {
	if siteType == SiteAWS {
		return 100
	}
	return configured
}

// AccountProtectionThreshold applies an instance's own threshold when one is
// set. An explicit per-instance value wins on AWS too: the user chose it.
func AccountProtectionThreshold(siteType string, override, configured float64) float64 {
	if override > 0 {
		return override
	}
	return ProtectionThreshold(siteType, configured)
}

// NewClient picks the cloud backend for an account's site type.
func NewClient(accessKey, secret, region, siteType string) Client {
	if siteType == SiteAWS {
		return NewLightsail(accessKey, secret, region)
	}
	return NewRPCService(accessKey, secret, region)
}

// Lightsail manages AWS Lightsail instances through the Client interface.
// Instances are identified by name, and a static IP plays the role of an EIP:
// its name is the allocation ID.
type Lightsail struct {
	AccessKey, Secret, Region string
	HTTPClient                *http.Client
	// Endpoint overrides https://lightsail.<region>.amazonaws.com/ in tests.
	Endpoint string
	// StaticIPPoll is how often a new static IP is checked for its address.
	StaticIPPoll time.Duration
}

// NewLightsail honours AWS_ENDPOINT_URL_LIGHTSAIL, the AWS SDKs' variable for
// pointing one service at another endpoint such as a local emulator.
func NewLightsail(accessKey, secret, region string) *Lightsail {
	return &Lightsail{AccessKey: accessKey, Secret: secret, Region: region, HTTPClient: &http.Client{Timeout: 30 * time.Second}, Endpoint: strings.TrimSpace(os.Getenv("AWS_ENDPOINT_URL_LIGHTSAIL"))}
}

const lightsailTargetPrefix = "Lightsail_20161128."

// LightsailRegions are the regions Lightsail is offered in.
var LightsailRegions = []struct{ ID, Name string }{
	{"us-east-1", "美国东部（弗吉尼亚）"},
	{"us-east-2", "美国东部（俄亥俄）"},
	{"us-west-2", "美国西部（俄勒冈）"},
	{"ca-central-1", "加拿大（蒙特利尔）"},
	{"eu-west-1", "欧洲（爱尔兰）"},
	{"eu-west-2", "欧洲（伦敦）"},
	{"eu-west-3", "欧洲（巴黎）"},
	{"eu-central-1", "欧洲（法兰克福）"},
	{"eu-north-1", "欧洲（斯德哥尔摩）"},
	{"ap-south-1", "亚太（孟买）"},
	{"ap-east-1", "亚太（香港）"},
	{"ap-southeast-1", "亚太（新加坡）"},
	{"ap-southeast-2", "亚太（悉尼）"},
	{"ap-southeast-3", "亚太（雅加达）"},
	{"ap-northeast-1", "亚太（东京）"},
	{"ap-northeast-2", "亚太（首尔）"},
}

func (l *Lightsail) regionOr(region string) string {
	if region != "" {
		return region
	}
	return l.Region
}

// call sends one Lightsail action (JSON 1.1 over a SigV4-signed POST).
func (l *Lightsail) call(ctx context.Context, region, action string, input map[string]any, output any) error {
	region = l.regionOr(region)
	if input == nil {
		input = map[string]any{}
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	host := "lightsail." + region + ".amazonaws.com"
	endpoint := "https://" + host + "/"
	if l.Endpoint != "" {
		endpoint = l.Endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	target := lightsailTargetPrefix + action
	const contentType = "application/x-amz-json-1.1"
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("Authorization", awsV4Authorization(l.AccessKey, l.Secret, region, "lightsail", http.MethodPost, "/", "", map[string]string{
		"content-type": contentType, "host": host, "x-amz-date": amzDate, "x-amz-target": target,
	}, body, amzDate))
	// The signature covers the real host even when a test endpoint is used.
	req.Host = host
	client := l.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return lightsailError(resp.StatusCode, raw)
	}
	if output == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, output)
}

func lightsailError(status int, raw []byte) error {
	var problem struct {
		Type    string `json:"__type"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Upper   string `json:"Message"`
	}
	_ = json.Unmarshal(raw, &problem)
	code := problem.Type
	if index := strings.LastIndex(code, "#"); index >= 0 {
		code = code[index+1:]
	}
	if code == "" {
		code = fallbackString(problem.Code, "HTTP"+strconv.Itoa(status))
	}
	message := fallbackString(problem.Message, problem.Upper)
	if message == "" {
		message = strings.TrimSpace(string(raw))
		if len(message) > 200 {
			message = message[:200]
		}
	}
	return &APIError{Provider: "aws", Code: code, Message: message, HTTPStatus: status}
}

func fallbackString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

// awsV4Authorization builds a SigV4 Authorization header. headers must use
// lowercase names and include every header that is sent signed.
func awsV4Authorization(accessKey, secret, region, service, method, path, query string, headers map[string]string, body []byte, amzDate string) string {
	date := amzDate[:8]
	scope := date + "/" + region + "/" + service + "/aws4_request"
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + strings.Join(strings.Fields(headers[name]), " ") + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	bodyHash := sha256.Sum256(body)
	canonicalRequest := strings.Join([]string{method, path, query, canonicalHeaders.String(), signedHeaders, hex.EncodeToString(bodyHash[:])}, "\n")
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(requestHash[:])
	key := awsHMAC([]byte("AWS4"+secret), date)
	key = awsHMAC(key, region)
	key = awsHMAC(key, service)
	key = awsHMAC(key, "aws4_request")
	return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + hex.EncodeToString(awsHMAC(key, stringToSign))
}

func awsHMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

type lightsailInstance struct {
	Name      string `json:"name"`
	Blueprint string `json:"blueprintName"`
	BundleID  string `json:"bundleId"`
	PublicIP  string `json:"publicIpAddress"`
	PrivateIP string `json:"privateIpAddress"`
	Hardware  struct {
		CPUCount    int     `json:"cpuCount"`
		RAMSizeInGB float64 `json:"ramSizeInGb"`
	} `json:"hardware"`
	State struct {
		Name string `json:"name"`
	} `json:"state"`
}

func (i lightsailInstance) toInstance() Instance {
	return Instance{
		ID: i.Name, Name: i.Name, Status: lightsailStatus(i.State.Name),
		PublicIP: i.PublicIP, PrivateIP: i.PrivateIP, InstanceType: i.BundleID,
		// The panel shows memory in MiB, as ECS reports it.
		CPU: i.Hardware.CPUCount, Memory: int(i.Hardware.RAMSizeInGB * 1024), OSName: i.Blueprint,
		ChargeType: "PostPaid",
	}
}

// lightsailStatus maps Lightsail states onto the ECS status names the panel
// and the monitor already understand.
func lightsailStatus(state string) string {
	switch strings.ToLower(state) {
	case "running":
		return "Running"
	case "stopped":
		return "Stopped"
	case "pending":
		return "Starting"
	case "stopping", "shutting-down":
		return "Stopping"
	}
	return "Unknown"
}

func (l *Lightsail) DescribeRegions(ctx context.Context) ([]map[string]any, error) {
	var response struct {
		Regions []struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"regions"`
	}
	if err := l.call(ctx, "", "GetRegions", nil, &response); err != nil {
		return nil, err
	}
	regions := make([]map[string]any, 0, len(response.Regions))
	for _, region := range response.Regions {
		regions = append(regions, map[string]any{"RegionId": region.Name, "LocalName": region.DisplayName})
	}
	return regions, nil
}

func (l *Lightsail) DescribeZones(context.Context, string) ([]map[string]any, error) {
	return nil, nil
}

func (l *Lightsail) DescribeInstances(ctx context.Context, region string) ([]Instance, error) {
	instances := make([]Instance, 0)
	token := ""
	for {
		input := map[string]any{}
		if token != "" {
			input["pageToken"] = token
		}
		var response struct {
			Instances     []lightsailInstance `json:"instances"`
			NextPageToken string              `json:"nextPageToken"`
		}
		if err := l.call(ctx, region, "GetInstances", input, &response); err != nil {
			return nil, err
		}
		for _, instance := range response.Instances {
			instances = append(instances, instance.toInstance())
		}
		if response.NextPageToken == "" {
			return instances, nil
		}
		token = response.NextPageToken
	}
}

func (l *Lightsail) DescribeInstance(ctx context.Context, region, id string) (*Instance, error) {
	var response struct {
		Instance *lightsailInstance `json:"instance"`
	}
	if err := l.call(ctx, region, "GetInstance", map[string]any{"instanceName": id}, &response); err != nil {
		return nil, err
	}
	if response.Instance == nil || response.Instance.Name == "" {
		return nil, &APIError{Provider: "aws", Code: "NotFoundException", Message: "instance " + id + " not found", HTTPStatus: 404}
	}
	instance := response.Instance.toInstance()
	return &instance, nil
}

func (l *Lightsail) StartInstance(ctx context.Context, region, id string) error {
	return l.call(ctx, region, "StartInstance", map[string]any{"instanceName": id}, nil)
}

// StopInstance ignores the ECS stop mode: a stopped Lightsail instance keeps
// billing for its plan either way.
func (l *Lightsail) StopInstance(ctx context.Context, region, id, _ string) error {
	return l.call(ctx, region, "StopInstance", map[string]any{"instanceName": id}, nil)
}

func (l *Lightsail) DeleteInstance(ctx context.Context, region, id string) error {
	return l.call(ctx, region, "DeleteInstance", map[string]any{"instanceName": id, "forceDeleteAddOns": true}, nil)
}

var errLightsailUnsupported = fmt.Errorf("AWS Lightsail 账号暂不支持此功能")

func (l *Lightsail) RunInstances(context.Context, RunRequest) (RunResult, error) {
	return RunResult{}, errLightsailUnsupported
}

func (l *Lightsail) PrepareNetwork(context.Context, string, string, string, string) (string, string, string, error) {
	return "", "", "", errLightsailUnsupported
}

func (l *Lightsail) CleanupNetwork(context.Context, string, string, string, string) error {
	return nil
}

func (l *Lightsail) GetBilling(context.Context, string, string, string) (float64, float64, string, error) {
	return 0, 0, "USD", fmt.Errorf("AWS Lightsail 账号暂不支持账单查询")
}

type lightsailStaticIP struct {
	Name       string `json:"name"`
	IPAddress  string `json:"ipAddress"`
	AttachedTo string `json:"attachedTo"`
	IsAttached bool   `json:"isAttached"`
}

func (l *Lightsail) staticIPs(ctx context.Context, region string) ([]lightsailStaticIP, error) {
	items := make([]lightsailStaticIP, 0)
	token := ""
	for {
		input := map[string]any{}
		if token != "" {
			input["pageToken"] = token
		}
		var response struct {
			StaticIPs     []lightsailStaticIP `json:"staticIps"`
			NextPageToken string              `json:"nextPageToken"`
		}
		if err := l.call(ctx, region, "GetStaticIps", input, &response); err != nil {
			return nil, err
		}
		items = append(items, response.StaticIPs...)
		if response.NextPageToken == "" {
			return items, nil
		}
		token = response.NextPageToken
	}
}

// DescribeInstancePublicNetworks reports the static IP attached to each
// instance; instances on a dynamic public IP are left out.
func (l *Lightsail) DescribeInstancePublicNetworks(ctx context.Context, region string, instanceIDs []string) (map[string]InstancePublicNetwork, error) {
	wanted := make(map[string]bool, len(instanceIDs))
	for _, id := range instanceIDs {
		wanted[id] = true
	}
	networks := map[string]InstancePublicNetwork{}
	if len(wanted) == 0 {
		return networks, nil
	}
	items, err := l.staticIPs(ctx, region)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.IsAttached && wanted[item.AttachedTo] {
			networks[item.AttachedTo] = InstancePublicNetwork{AllocationID: item.Name, Address: item.IPAddress}
		}
	}
	return networks, nil
}

func (l *Lightsail) DescribeEIP(ctx context.Context, region, allocationID string) (*EIPDetail, error) {
	var response struct {
		StaticIP *lightsailStaticIP `json:"staticIp"`
	}
	if err := l.call(ctx, region, "GetStaticIp", map[string]any{"staticIpName": allocationID}, &response); err != nil {
		return nil, err
	}
	if response.StaticIP == nil || response.StaticIP.Name == "" {
		return nil, &APIError{Provider: "aws", Code: "NotFoundException", Message: "static IP " + allocationID + " not found", HTTPStatus: 404}
	}
	detail := &EIPDetail{AllocationID: response.StaticIP.Name, Address: response.StaticIP.IPAddress, Status: "Available", ChargeType: "PostPaid"}
	if response.StaticIP.IsAttached {
		detail.Status, detail.InstanceID = "InUse", response.StaticIP.AttachedTo
	}
	return detail, nil
}

// AllocateEIP creates a static IP and returns its name and address.
func (l *Lightsail) AllocateEIP(ctx context.Context, region string) (string, string, error) {
	name := "ecs-controller-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := l.call(ctx, region, "AllocateStaticIp", map[string]any{"staticIpName": name}, nil); err != nil {
		return "", "", err
	}
	poll := l.StaticIPPoll
	if poll <= 0 {
		poll = time.Second
	}
	var lastErr error
	for attempt := 0; attempt < 10 && ctx.Err() == nil; attempt++ {
		detail, err := l.DescribeEIP(ctx, region, name)
		if err == nil && detail.Address != "" {
			return name, detail.Address, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			lastErr = ctx.Err()
		case <-time.After(poll):
		}
	}
	// Do not leave an address behind that the caller never learned about.
	_ = l.ReleaseEIP(context.WithoutCancel(ctx), region, name)
	if lastErr == nil {
		lastErr = fmt.Errorf("静态 IP %s 没有返回地址", name)
	}
	return "", "", lastErr
}

// AllocateEIPLike ignores the template: Lightsail static IPs have no line or
// bandwidth options.
func (l *Lightsail) AllocateEIPLike(ctx context.Context, region string, _ EIPDetail) (string, string, error) {
	return l.AllocateEIP(ctx, region)
}

func (l *Lightsail) AssociateEIP(ctx context.Context, region, allocationID, instanceID string) error {
	return l.call(ctx, region, "AttachStaticIp", map[string]any{"staticIpName": allocationID, "instanceName": instanceID}, nil)
}

func (l *Lightsail) UnassociateEIP(ctx context.Context, region, allocationID string) error {
	return l.call(ctx, region, "DetachStaticIp", map[string]any{"staticIpName": allocationID}, nil)
}

func (l *Lightsail) ReleaseEIP(ctx context.Context, region, allocationID string) error {
	return l.call(ctx, region, "ReleaseStaticIp", map[string]any{"staticIpName": allocationID}, nil)
}

// transfer sums NetworkIn and NetworkOut for one instance. Lightsail counts
// both directions against the plan's monthly transfer allowance.
func (l *Lightsail) transfer(ctx context.Context, region, instanceID string, startMS, endMS int64, period int) (bytes float64, lastMS int64, points int, err error) {
	if endMS <= startMS {
		return 0, startMS, 0, nil
	}
	for _, metric := range []string{"NetworkOut", "NetworkIn"} {
		var response struct {
			MetricData []struct {
				Sum       float64 `json:"sum"`
				Timestamp float64 `json:"timestamp"`
			} `json:"metricData"`
		}
		input := map[string]any{
			"instanceName": instanceID, "metricName": metric, "period": period,
			"startTime": startMS / 1000, "endTime": endMS / 1000, "unit": "Bytes", "statistics": []string{"Sum"},
		}
		if err := l.call(ctx, region, "GetInstanceMetricData", input, &response); err != nil {
			return 0, startMS, 0, err
		}
		for _, point := range response.MetricData {
			if point.Sum > 0 {
				bytes += point.Sum
			}
			if ts := int64(point.Timestamp * 1000); ts > lastMS {
				lastMS = ts
			}
			if metric == "NetworkOut" {
				points++
			}
		}
	}
	if lastMS == 0 {
		lastMS = startMS
	}
	return bytes, lastMS, points, nil
}

// GetOutboundTrafficDelta returns the transfer since startMS in five-minute
// datapoints. The next call resumes after the last complete datapoint.
func (l *Lightsail) GetOutboundTrafficDelta(ctx context.Context, region, instanceID, _ string, startMS, endMS int64) (float64, int64, int, string, error) {
	const period = 300
	periodMS := int64(period * 1000)
	// Whole periods only, so two consecutive windows never share a datapoint,
	// and one period behind now, because the newest datapoint arrives late.
	startMS, endMS = (startMS+periodMS-1)/periodMS*periodMS, (endMS-periodMS)/periodMS*periodMS
	if endMS <= startMS {
		return 0, startMS, 0, "", nil
	}
	bytes, _, points, err := l.transfer(ctx, region, instanceID, startMS, endMS, period)
	if err != nil {
		return 0, startMS, 0, "", err
	}
	if points == 0 {
		return 0, startMS, 0, "", fmt.Errorf("%w: Lightsail 没有返回 %s 的流量数据", ErrMetricNoData, instanceID)
	}
	return bytes, endMS, points, "NetworkOut+NetworkIn", nil
}

// GetInstanceMonthlyTraffic sums the instance's transfer between startMS and
// endMS in hourly datapoints.
func (l *Lightsail) GetInstanceMonthlyTraffic(ctx context.Context, region, instanceID, _ string, startMS, endMS int64) (float64, int, error) {
	bytes, _, points, err := l.transfer(ctx, region, instanceID, startMS, endMS, 3600)
	return bytes, points, err
}

var lightsailTrafficCache sync.Map // "accessKey|region|month" -> lightsailTrafficEntry

type lightsailTrafficEntry struct {
	gb float64
	at time.Time
}

// GetTraffic is this month's transfer of every instance in the region, in GB.
// It stands in for the account-level CDT total of Alibaba Cloud and is cached
// for five minutes because it costs two metric calls per instance.
func (l *Lightsail) GetTraffic(ctx context.Context, region string) (float64, error) {
	region = l.regionOr(region)
	now := time.Now()
	key := l.AccessKey + "|" + region + "|" + now.Format("2006-01") + "|" + l.Endpoint
	if cached, ok := lightsailTrafficCache.Load(key); ok {
		if entry := cached.(lightsailTrafficEntry); now.Sub(entry.at) < 5*time.Minute {
			return entry.gb, nil
		}
	}
	instances, err := l.DescribeInstances(ctx, region)
	if err != nil {
		return 0, err
	}
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).UnixMilli()
	total := 0.0
	for _, instance := range instances {
		bytes, _, _, err := l.transfer(ctx, region, instance.ID, monthStart, now.UnixMilli(), 3600)
		if err != nil {
			return 0, err
		}
		total += bytes
	}
	gb := total / (1024 * 1024 * 1024)
	lightsailTrafficCache.Store(key, lightsailTrafficEntry{gb: gb, at: now})
	return gb, nil
}

// TestAccount checks the read APIs the panel depends on. Start, stop and
// static IP changes cannot be dry-run on Lightsail, so they stay unchecked.
func (l *Lightsail) TestAccount(parent context.Context, region, _ string) AccountTestResult {
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	const policy = "lightsail:*（或下方 README 中的最小权限策略）"
	checks := []PermissionCheck{
		{ID: "ls_read", Name: "查看实例", Required: true, Policy: policy},
		{ID: "ls_static_ip", Name: "查看静态 IP", Required: true, Policy: policy},
		{ID: "ls_metrics", Name: "实例流量", Required: true, Policy: policy},
		{ID: "ls_power", Name: "开机 / 关机", Required: true, Policy: policy},
		{ID: "ls_static_ip_manage", Name: "更换公网 IP（创建 / 绑定 / 释放静态 IP）", Required: true, Policy: policy},
		{ID: "ls_delete", Name: "释放实例", Policy: policy},
	}
	for i := range checks {
		checks[i].Status = "unchecked"
		checks[i].Message = "未执行真实操作，请在 AWS IAM 确认已添加此权限"
	}
	result := AccountTestResult{Checks: checks}
	fail := func(index int, err error) bool {
		var apiErr *APIError
		check := &checks[index]
		check.Status, check.Message = "unavailable", "暂时无法检查，请检查网络后重试: "+err.Error()
		if !errors.As(err, &apiErr) {
			return false
		}
		check.ErrorCode = apiErr.Code
		code := strings.ToLower(apiErr.Code)
		switch {
		case strings.Contains(code, "unrecognizedclient") || strings.Contains(code, "invalidclienttokenid") || strings.Contains(code, "signature"):
			check.Message = "账号密钥无效，请检查 Access Key ID 和 Secret Access Key"
			return true
		case strings.Contains(code, "accessdenied") || strings.Contains(code, "unauthorized"):
			check.Status, check.Message = "missing", "缺少权限: "+apiErr.Message
		}
		return false
	}
	instances, err := l.DescribeInstances(ctx, region)
	if err != nil {
		if fail(0, err) {
			for i := 1; i < len(checks); i++ {
				checks[i].Message = "账号验证失败，未继续检查"
			}
			result.Status, result.Message = "error", "账号密钥无效，请检查 Access Key ID 和 Secret Access Key"
			return result
		}
	} else {
		checks[0].Status, checks[0].Message = "ok", "可以查看当前区域的实例"
		result.Success = true
		count := len(instances)
		result.InstanceCount = &count
	}
	if _, err := l.staticIPs(ctx, region); err != nil {
		fail(1, err)
	} else {
		checks[1].Status, checks[1].Message = "ok", "可以查看静态 IP"
	}
	if len(instances) > 0 {
		end := time.Now().UnixMilli()
		if _, _, _, err := l.transfer(ctx, region, instances[0].ID, end-int64(time.Hour/time.Millisecond), end, 300); err != nil {
			fail(2, err)
		} else {
			checks[2].Status, checks[2].Message = "ok", "可以读取实例流量"
		}
	} else {
		checks[2].Message = "当前区域没有实例，无法检查流量接口"
	}
	missing, pending := 0, 0
	for _, check := range checks {
		switch check.Status {
		case "missing":
			missing++
		case "unavailable":
			pending++
		}
	}
	result.Status = "warning"
	switch {
	case missing > 0:
		result.Status = "missing"
		result.Message = fmt.Sprintf("发现 %d 项缺少权限，请按下方提示补充", missing)
	case pending > 0:
		result.Message = "本次有项目未能确认，请按下方提示处理；未验证不代表没有权限"
	default:
		result.Status, result.Message = "ok", "读取权限已通过；开关机和更换 IP 权限无法预检，请确认 IAM 策略包含 Lightsail 操作权限"
	}
	return result
}
