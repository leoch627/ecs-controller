package cloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// OSSClient is the small slice of the OSS REST API needed to stage a disk
// image for ECS ImportImage: create a bucket, upload one object, and remove
// both again. Requests are signed with the OSS V4 signature.
type OSSClient struct {
	HTTPClient *http.Client
	AccessKey  string
	Secret     string
	Region     string
	// Endpoint overrides the default https://<bucket>.oss-<region>.aliyuncs.com
	// host. Tests point it at a local server; it is used path-style.
	Endpoint string
	// Now is replaceable so signatures are reproducible in tests.
	Now func() time.Time
}

type OSSError struct {
	Code       string `xml:"Code"`
	Message    string `xml:"Message"`
	HTTPStatus int    `xml:"-"`
}

func (e *OSSError) Error() string { return fmt.Sprintf("oss %s: %s", e.Code, e.Message) }

func (c *OSSClient) PutBucket(ctx context.Context, bucket string) error {
	body := `<?xml version="1.0" encoding="UTF-8"?><CreateBucketConfiguration><StorageClass>Standard</StorageClass></CreateBucketConfiguration>`
	headers := map[string]string{"x-oss-acl": "private", "Content-Type": "application/xml"}
	err := c.do(ctx, http.MethodPut, bucket, "", headers, strings.NewReader(body), int64(len(body)))
	if ossErr, ok := err.(*OSSError); ok && ossErr.Code == "BucketAlreadyExists" && c.bucketOwned(ctx, bucket) {
		return nil
	}
	return err
}

// bucketOwned reports whether the caller can already read the bucket, which
// separates "we created it on an earlier attempt" from a name collision.
func (c *OSSClient) bucketOwned(ctx context.Context, bucket string) bool {
	return c.do(ctx, http.MethodHead, bucket, "", nil, nil, 0) == nil
}

func (c *OSSClient) PutObject(ctx context.Context, bucket, key string, body io.Reader, size int64) error {
	return c.do(ctx, http.MethodPut, bucket, key, map[string]string{"Content-Type": "application/octet-stream"}, body, size)
}

func (c *OSSClient) DeleteObject(ctx context.Context, bucket, key string) error {
	return c.do(ctx, http.MethodDelete, bucket, key, nil, nil, 0)
}

func (c *OSSClient) DeleteBucket(ctx context.Context, bucket string) error {
	return c.do(ctx, http.MethodDelete, bucket, "", nil, nil, 0)
}

func (c *OSSClient) do(ctx context.Context, method, bucket, key string, headers map[string]string, body io.Reader, size int64) error {
	if c == nil || c.AccessKey == "" || c.Secret == "" || c.Region == "" {
		return fmt.Errorf("oss client is not configured")
	}
	target := "https://" + bucket + ".oss-" + c.Region + ".aliyuncs.com/" + ossEscapePath(key)
	if c.Endpoint != "" {
		target = strings.TrimRight(c.Endpoint, "/") + "/" + bucket + "/" + ossEscapePath(key)
	}
	if body == nil {
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	c.sign(req, bucket, key, now)
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 300 {
		return nil
	}
	ossErr := &OSSError{HTTPStatus: resp.StatusCode}
	if xml.Unmarshal(payload, ossErr) != nil || ossErr.Code == "" {
		ossErr.Code = fmt.Sprintf("HTTP%d", resp.StatusCode)
		ossErr.Message = strings.TrimSpace(string(bytes.TrimSpace(payload)))
	}
	return ossErr
}

func (c *OSSClient) sign(req *http.Request, bucket, key string, now time.Time) {
	now = now.UTC()
	datetime, date := now.Format("20060102T150405Z"), now.Format("20060102")
	req.Header.Set("x-oss-date", datetime)
	req.Header.Set("x-oss-content-sha256", "UNSIGNED-PAYLOAD")

	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		low := strings.ToLower(name)
		if strings.HasPrefix(low, "x-oss-") || low == "content-type" || low == "content-md5" {
			names = append(names, low)
		}
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + strings.TrimSpace(req.Header.Get(name)) + "\n")
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		ossEscapePath("/" + bucket + "/" + key),
		ossCanonicalQuery(req.URL.RawQuery),
		canonicalHeaders.String(),
		"", // no additional signed headers
		"UNSIGNED-PAYLOAD",
	}, "\n")
	scope := date + "/" + c.Region + "/oss/aliyun_v4_request"
	digest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "OSS4-HMAC-SHA256\n" + datetime + "\n" + scope + "\n" + hex.EncodeToString(digest[:])

	signingKey := []byte("aliyun_v4" + c.Secret)
	for _, part := range []string{date, c.Region, "oss", "aliyun_v4_request"} {
		signingKey = hmacSHA256(signingKey, part)
	}
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set("Authorization", "OSS4-HMAC-SHA256 Credential="+c.AccessKey+"/"+scope+",Signature="+signature)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(data))
	return h.Sum(nil)
}

func ossCanonicalQuery(raw string) string {
	raw = strings.ReplaceAll(raw, "+", "%20")
	values := map[string]string{}
	keys := make([]string, 0)
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		values[key] = value
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if values[key] != "" {
			parts = append(parts, key+"="+values[key])
		} else {
			parts = append(parts, key)
		}
	}
	return strings.Join(parts, "&")
}

func ossEscapePath(path string) string {
	var buf strings.Builder
	for i := 0; i < len(path); i++ {
		ch := path[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' || ch == '_' || ch == '~' || ch == '/' {
			buf.WriteByte(ch)
		} else {
			fmt.Fprintf(&buf, "%%%02X", ch)
		}
	}
	return buf.String()
}
