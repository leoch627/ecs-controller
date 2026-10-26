package dns

import "testing"

// Expected values were produced by each vendor's official SDK signing the same
// inputs with the same fixed timestamp: huaweicloudsdkcore (Python), the
// tencentcloud-sdk-python TC3 signer, and botocore's SigV4Auth.

func TestHuaweiSignatureMatchesOfficialSDK(t *testing.T) {
	host := "dns.cn-north-4.myhuaweicloud.com"
	cases := []struct {
		method, path string
		query        map[string]string
		body, want   string
	}{
		{"GET", "/v2/zones", map[string]string{"type": "public", "name": "example.com.", "search_mode": "equal", "limit": "50"}, "",
			"SDK-HMAC-SHA256 Access=AKDEMO123, SignedHeaders=content-type;host;x-sdk-date, Signature=0aaa7e02cdb9953fc96a67d2ef13af10b24c600ecb9ea4ae70919c44447cb45d"},
		{"GET", "/v2.1/recordsets", map[string]string{"zone_type": "public", "type": "A", "records": "47.242.10.21", "limit": "500", "offset": "0", "zone_id": "ff8080826c"}, "",
			"SDK-HMAC-SHA256 Access=AKDEMO123, SignedHeaders=content-type;host;x-sdk-date, Signature=62a1d319896a78e423618e0dd58ed7263b0f72a7f8adfd5bb372e413a7ee6b1d"},
		{"PUT", "/v2.1/zones/ff8080826c/recordsets/ff80abc", nil, `{"name":"hk.example.com.","type":"A","ttl":300,"records":["1.2.3.4"]}`,
			"SDK-HMAC-SHA256 Access=AKDEMO123, SignedHeaders=content-type;host;x-sdk-date, Signature=fde554e858ddf7ef284f7f224afccdf1207d679532edfa5d2925663249735481"},
		{"DELETE", "/v2.1/zones/ff8080826c/recordsets/ff80abc", nil, "",
			"SDK-HMAC-SHA256 Access=AKDEMO123, SignedHeaders=content-type;host;x-sdk-date, Signature=6fc22c32d9f4581d49ec7014654ae833cd200cc1ab2f46f5e3d54c426fe43c13"},
	}
	for _, c := range cases {
		got := huaweiAuthorization("AKDEMO123", "SKdemo/secret+456", c.method, host, c.path, huaweiCanonicalQuery(c.query), []byte(c.body), "20261025T120000Z")
		if got != c.want {
			t.Errorf("%s %s\n got  %s\n want %s", c.method, c.path, got, c.want)
		}
	}
}

func TestDNSPodSignatureMatchesOfficialSDK(t *testing.T) {
	cases := []struct {
		host    string
		ts      int64
		payload string
		want    string
	}{
		{"dnspod.tencentcloudapi.com", 1793001600, `{"Domain":"example.com","RecordType":"A","Limit":3000,"ErrorOnEmpty":"no","Keyword":"47.242.10.21","Offset":0}`,
			"TC3-HMAC-SHA256 Credential=AKIDdemo/2026-10-26/dnspod/tc3_request, SignedHeaders=content-type;host, Signature=f1f632be502c5decc800c9c8d2fdb856846ccff22d705b5d6a28d05ab2d7e532"},
		{"dnspod.intl.tencentcloudapi.com", 1793005200, `{"Domain":"example.com","SubDomain":"hk","RecordType":"A","RecordLine":"默认","Value":"1.2.3.4","TTL":600}`,
			"TC3-HMAC-SHA256 Credential=AKIDdemo/2026-10-26/dnspod/tc3_request, SignedHeaders=content-type;host, Signature=3b6e1b83ffa938d93b8320f3f1f6e6b82526b2a224d39838da2828e0f49f1b4e"},
	}
	for _, c := range cases {
		if got := dnspodAuthorization("AKIDdemo", "skey-demo/+=", c.host, []byte(c.payload), c.ts); got != c.want {
			t.Errorf("%s\n got  %s\n want %s", c.host, got, c.want)
		}
	}
}

func TestRoute53SignatureMatchesBotocore(t *testing.T) {
	deleteBody := `<?xml version="1.0" encoding="UTF-8"?><ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Changes><Change><Action>DELETE</Action><ResourceRecordSet><Name>hk.example.com.</Name><Type>A</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>47.242.10.21</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
	cases := []struct {
		method, path, query, body, want string
	}{
		{"GET", "/2013-04-01/hostedzone", "maxitems=100", "",
			"AWS4-HMAC-SHA256 Credential=AKIADEMO/20261025/us-east-1/route53/aws4_request, SignedHeaders=host;x-amz-date, Signature=8f9fc77ea25d5a1ce3bcf3d5381166ebfb761f10761a295c40428d93c7011b74"},
		{"GET", "/2013-04-01/hostedzone/Z1EXAMPLE/rrset", "maxitems=300&name=hk.example.com.&type=A", "",
			"AWS4-HMAC-SHA256 Credential=AKIADEMO/20261025/us-east-1/route53/aws4_request, SignedHeaders=host;x-amz-date, Signature=313f8b5c5a451d3bf0ed8a3b6b19c3597bcc5ff8b1e21813bdae8eee54444641"},
		{"POST", "/2013-04-01/hostedzone/Z1EXAMPLE/rrset/", "", deleteBody,
			"AWS4-HMAC-SHA256 Credential=AKIADEMO/20261025/us-east-1/route53/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=25b6b91cd7ccd710f663ebcd768b3a868a0c843e063ea9bfb9ff28d7f176252d"},
	}
	for _, c := range cases {
		headers := map[string]string{"host": route53Host, "x-amz-date": "20261025T120000Z"}
		if c.body != "" {
			headers["content-type"] = "text/xml"
		}
		if got := route53Authorization("AKIADEMO", "secret/demo+key", c.method, c.path, c.query, headers, c.body, "20261025T120000Z"); got != c.want {
			t.Errorf("%s %s\n got  %s\n want %s", c.method, c.path, got, c.want)
		}
	}
}

func TestRoute53QueryEncodingMatchesSigningInput(t *testing.T) {
	got := huaweiCanonicalQuery(map[string]string{"type": "A", "name": "hk.example.com.", "maxitems": "300"})
	if got != "maxitems=300&name=hk.example.com.&type=A" {
		t.Fatalf("canonical query = %q", got)
	}
}
