package dns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"html"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// route53 is AWS Route 53 (REST XML, SigV4, global endpoint in us-east-1).
// Record sets using routing policies (SetIdentifier) or aliases are skipped so
// cleanup can never break a weighted, failover or latency configuration.
type route53 struct {
	cfg  Config
	http *http.Client
}

const (
	route53Host  = "route53.amazonaws.com"
	route53Xmlns = "https://route53.amazonaws.com/doc/2013-04-01/"
)

type route53RecordSet struct {
	Name            string    `xml:"Name"`
	Type            string    `xml:"Type"`
	TTL             int       `xml:"TTL"`
	SetIdentifier   *string   `xml:"SetIdentifier"`
	AliasTarget     *struct{} `xml:"AliasTarget"`
	ResourceRecords []struct {
		Value string `xml:"Value"`
	} `xml:"ResourceRecords>ResourceRecord"`
}

func (r *route53) ListZones(ctx context.Context) ([]Zone, error) {
	zones := make([]Zone, 0)
	marker := ""
	for {
		query := map[string]string{"maxitems": "100"}
		if marker != "" {
			query["marker"] = marker
		}
		var response struct {
			HostedZones []struct {
				ID          string `xml:"Id"`
				Name        string `xml:"Name"`
				PrivateZone bool   `xml:"Config>PrivateZone"`
			} `xml:"HostedZones>HostedZone"`
			IsTruncated bool   `xml:"IsTruncated"`
			NextMarker  string `xml:"NextMarker"`
		}
		if err := r.api(ctx, http.MethodGet, "/2013-04-01/hostedzone", query, "", &response); err != nil {
			return nil, err
		}
		for _, zone := range response.HostedZones {
			if !zone.PrivateZone {
				zones = append(zones, Zone{ID: route53ZoneID(zone.ID), Name: route53Unescape(zone.Name)})
			}
		}
		if !response.IsTruncated {
			return zones, nil
		}
		marker = response.NextMarker
	}
}

func (r *route53) ListA(ctx context.Context, zone Zone, name, ip string) ([]Record, error) {
	records := make([]Record, 0)
	query := map[string]string{"maxitems": "300"}
	if name != "" {
		// name/type mark where the listing starts, not a filter: stop at the first other name.
		query["name"] = normalizeName(name) + "."
		query["type"] = "A"
	}
	for {
		var response struct {
			RecordSets           []route53RecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
			IsTruncated          bool               `xml:"IsTruncated"`
			NextRecordName       string             `xml:"NextRecordName"`
			NextRecordType       string             `xml:"NextRecordType"`
			NextRecordIdentifier string             `xml:"NextRecordIdentifier"`
		}
		if err := r.api(ctx, http.MethodGet, "/2013-04-01/hostedzone/"+route53ZoneID(zone.ID)+"/rrset", query, "", &response); err != nil {
			return nil, err
		}
		passedName := false
		for _, set := range response.RecordSets {
			setName := route53Unescape(set.Name)
			if name != "" && setName != normalizeName(name) {
				passedName = true
				break
			}
			if set.Type != "A" || set.SetIdentifier != nil || set.AliasTarget != nil {
				continue
			}
			values := make([]string, 0, len(set.ResourceRecords))
			for _, rr := range set.ResourceRecords {
				values = append(values, strings.TrimSpace(rr.Value))
			}
			records = append(records, Record{ID: setName, Name: setName, Values: values, TTL: set.TTL, Raw: map[string]any{"name": set.Name}})
		}
		if passedName || !response.IsTruncated {
			return filterRecords(records, name, ip), nil
		}
		query["name"], query["type"] = response.NextRecordName, response.NextRecordType
		if response.NextRecordIdentifier != "" {
			query["identifier"] = response.NextRecordIdentifier
		} else {
			delete(query, "identifier")
		}
	}
}

func (r *route53) CreateA(ctx context.Context, zone Zone, name, ip string) error {
	return r.change(ctx, zone, "CREATE", normalizeName(name)+".", 300, []string{ip})
}

func (r *route53) UpdateA(ctx context.Context, zone Zone, record Record, values []string) error {
	return r.change(ctx, zone, "UPSERT", r.rawName(record), record.TTL, values)
}

// DeleteA must repeat the record's exact TTL and values or Route 53 rejects it.
func (r *route53) DeleteA(ctx context.Context, zone Zone, record Record) error {
	return r.change(ctx, zone, "DELETE", r.rawName(record), record.TTL, record.Values)
}

func (r *route53) rawName(record Record) string {
	if name, _ := record.Raw["name"].(string); name != "" {
		return name
	}
	return record.Name + "."
}

func (r *route53) change(ctx context.Context, zone Zone, action, name string, ttl int, values []string) error {
	var records strings.Builder
	for _, value := range values {
		records.WriteString("<ResourceRecord><Value>" + html.EscapeString(value) + "</Value></ResourceRecord>")
	}
	body := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<ChangeResourceRecordSetsRequest xmlns="` + route53Xmlns + `"><ChangeBatch><Changes><Change>` +
		"<Action>" + action + "</Action>" +
		"<ResourceRecordSet><Name>" + html.EscapeString(name) + "</Name><Type>A</Type><TTL>" + strconv.Itoa(ttl) + "</TTL>" +
		"<ResourceRecords>" + records.String() + "</ResourceRecords></ResourceRecordSet>" +
		"</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"
	return r.api(ctx, http.MethodPost, "/2013-04-01/hostedzone/"+route53ZoneID(zone.ID)+"/rrset/", nil, body, nil)
}

func (r *route53) api(ctx context.Context, method, path string, query map[string]string, body string, output any) error {
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	queryString := huaweiCanonicalQuery(query)
	headers := map[string]string{"host": route53Host, "x-amz-date": amzDate}
	if body != "" {
		headers["content-type"] = "text/xml"
	}
	header := http.Header{
		"X-Amz-Date":    {amzDate},
		"Authorization": {route53Authorization(r.cfg.get("access_key_id"), r.cfg.get("secret_access_key"), method, path, queryString, headers, body, amzDate)},
	}
	if body != "" {
		header.Set("Content-Type", "text/xml")
	}
	endpoint := "https://" + route53Host + path
	if queryString != "" {
		endpoint += "?" + queryString
	}
	status, raw, err := doHTTP(ctx, r.http, "AWS Route 53", method, endpoint, header, []byte(body))
	if err != nil {
		return err
	}
	if status >= 400 {
		var problem struct {
			Code    string `xml:"Error>Code"`
			Message string `xml:"Error>Message"`
		}
		detail := truncate(string(raw), 200)
		if xml.Unmarshal(raw, &problem) == nil && problem.Code != "" {
			detail = problem.Code + " " + problem.Message
		}
		return providerError("AWS Route 53", status, detail)
	}
	if output != nil {
		if err := xml.Unmarshal(raw, output); err != nil {
			return providerError("AWS Route 53", status, "响应无法解析")
		}
	}
	return nil
}

// route53Authorization builds the SigV4 Authorization header (region us-east-1).
// headers must use lowercase names.
func route53Authorization(accessKey, secretKey, method, path, queryString string, headers map[string]string, body, amzDate string) string {
	date := amzDate[:8]
	scope := date + "/us-east-1/route53/aws4_request"
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
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = rfc3986(segment)
	}
	bodyHash := sha256.Sum256([]byte(body))
	canonicalRequest := strings.Join([]string{method, strings.Join(segments, "/"), queryString, canonicalHeaders.String(), signedHeaders, hex.EncodeToString(bodyHash[:])}, "\n")
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(requestHash[:])
	key := hmacSHA256([]byte("AWS4"+secretKey), date)
	key = hmacSHA256(key, "us-east-1")
	key = hmacSHA256(key, "route53")
	key = hmacSHA256(key, "aws4_request")
	return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + hex.EncodeToString(hmacSHA256(key, stringToSign))
}

func route53ZoneID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "/")
	return strings.TrimPrefix(id, "hostedzone/")
}

var route53Octal = regexp.MustCompile(`\\([0-7]{3})`)

// route53Unescape decodes Route 53's octal escapes (\052 is *).
func route53Unescape(name string) string {
	name = route53Octal.ReplaceAllStringFunc(name, func(match string) string {
		code, _ := strconv.ParseInt(match[1:], 8, 32)
		return string(rune(code))
	})
	return normalizeName(name)
}
