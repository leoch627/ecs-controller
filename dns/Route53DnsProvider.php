<?php

/**
 * AWS Route 53（REST XML，SigV4 签名，全局服务固定 us-east-1）。
 * 带路由策略（SetIdentifier）或别名（AliasTarget）的记录不做修改，避免破坏复杂配置。
 */
class Route53DnsProvider extends DnsProvider
{
    const HOST = 'route53.amazonaws.com';
    const XMLNS = 'https://route53.amazonaws.com/doc/2013-04-01/';

    public static function id()
    {
        return 'route53';
    }

    public static function label()
    {
        return 'AWS Route 53';
    }

    public static function defaultTtl()
    {
        return 300;
    }

    public static function fields()
    {
        return [
            ['key' => 'access_key_id', 'label' => 'Access Key ID', 'type' => 'text', 'required' => true, 'placeholder' => 'AKIA…'],
            ['key' => 'secret_access_key', 'label' => 'Secret Access Key', 'type' => 'secret', 'required' => true],
            ['key' => 'zone_id', 'label' => 'Hosted Zone ID', 'type' => 'text', 'placeholder' => '留空自动查询']
        ];
    }

    public static function permissionHint()
    {
        return 'IAM 策略需要 route53:ListHostedZones、route53:ListResourceRecordSets、route53:ChangeResourceRecordSets。带路由策略或别名的记录会被跳过。';
    }

    protected function fetchZones()
    {
        $zones = [];
        $marker = null;
        do {
            $query = ['maxitems' => '100'];
            if ($marker !== null) {
                $query['marker'] = $marker;
            }
            $xml = $this->api('GET', '/2013-04-01/hostedzone', $query);
            foreach ($xml->HostedZones->HostedZone ?? [] as $zone) {
                if ((string) ($zone->Config->PrivateZone ?? 'false') === 'true') {
                    continue;
                }
                $zones[] = ['id' => self::zoneId((string) $zone->Id), 'name' => self::unescape((string) $zone->Name)];
            }
            $marker = ((string) $xml->IsTruncated === 'true') ? (string) $xml->NextMarker : null;
        } while ($marker !== null);
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $records = [];
        $query = ['maxitems' => '300'];
        if ($name !== null) {
            // name/type 是起始位置而不是过滤条件，读到别的名字就可以停了
            $query['name'] = self::normalizeName($name) . '.';
            $query['type'] = 'A';
        }

        while (true) {
            $xml = $this->api('GET', '/2013-04-01/hostedzone/' . rawurlencode(self::zoneId($zone['id'])) . '/rrset', $query);
            $passedName = false;
            foreach ($xml->ResourceRecordSets->ResourceRecordSet ?? [] as $set) {
                $setName = self::unescape((string) $set->Name);
                if ($name !== null && $setName !== self::normalizeName($name)) {
                    $passedName = true;
                    break;
                }
                if ((string) $set->Type !== 'A' || isset($set->SetIdentifier) || isset($set->AliasTarget)) {
                    continue;
                }
                $values = [];
                foreach ($set->ResourceRecords->ResourceRecord ?? [] as $rr) {
                    $values[] = trim((string) $rr->Value);
                }
                $records[] = [
                    'id' => $setName,
                    'name' => $setName,
                    'values' => $values,
                    'ttl' => (int) $set->TTL,
                    'raw' => ['Name' => (string) $set->Name, 'TTL' => (int) $set->TTL]
                ];
            }

            if ($passedName || (string) $xml->IsTruncated !== 'true') {
                break;
            }
            $query['name'] = (string) $xml->NextRecordName;
            $query['type'] = (string) $xml->NextRecordType;
            if (isset($xml->NextRecordIdentifier)) {
                $query['identifier'] = (string) $xml->NextRecordIdentifier;
            } else {
                unset($query['identifier']);
            }
        }

        return self::filterRecords($records, $name, $ip);
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->change($zone, 'CREATE', self::normalizeName($name) . '.', $this->ttl(), [$ip]);
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $this->change($zone, 'UPSERT', $record['raw']['Name'], $record['ttl'], $values);
    }

    public function deleteARecord(array $zone, array $record)
    {
        // DELETE 必须和现有记录的 TTL、值完全一致
        $this->change($zone, 'DELETE', $record['raw']['Name'], $record['ttl'], $record['values']);
    }

    private function change(array $zone, $action, $name, $ttl, array $values)
    {
        $records = '';
        foreach ($values as $value) {
            $records .= '<ResourceRecord><Value>' . htmlspecialchars($value, ENT_XML1) . '</Value></ResourceRecord>';
        }
        $body = '<?xml version="1.0" encoding="UTF-8"?>'
            . '<ChangeResourceRecordSetsRequest xmlns="' . self::XMLNS . '"><ChangeBatch><Changes><Change>'
            . '<Action>' . $action . '</Action>'
            . '<ResourceRecordSet><Name>' . htmlspecialchars($name, ENT_XML1) . '</Name><Type>A</Type><TTL>' . (int) $ttl . '</TTL>'
            . '<ResourceRecords>' . $records . '</ResourceRecords></ResourceRecordSet>'
            . '</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>';

        $this->api('POST', '/2013-04-01/hostedzone/' . rawurlencode(self::zoneId($zone['id'])) . '/rrset/', [], $body);
    }

    private static function zoneId($id)
    {
        return preg_replace('#^/?hostedzone/#', '', trim((string) $id));
    }

    /** Route 53 用 \052 这类八进制转义表示 * 等字符 */
    private static function unescape($name)
    {
        $name = preg_replace_callback('/\\\\([0-7]{3})/', function ($m) {
            return chr(octdec($m[1]));
        }, $name);
        return self::normalizeName($name);
    }

    private function api($method, $path, array $query = [], $body = '')
    {
        $amzDate = gmdate('Ymd\THis\Z');
        $queryString = self::canonicalQuery($query);
        $headers = ['Host' => self::HOST, 'X-Amz-Date' => $amzDate];
        if ($body !== '') {
            $headers['Content-Type'] = 'text/xml';
        }
        $headers['Authorization'] = $this->authorization($method, $path, $queryString, $headers, $body, $amzDate);

        [$status, $raw] = $this->request($method, 'https://' . self::HOST . $path . ($queryString !== '' ? '?' . $queryString : ''), $headers, $body);

        $previous = libxml_use_internal_errors(true);
        $xml = $raw === '' ? null : simplexml_load_string($raw);
        libxml_use_internal_errors($previous);

        if ($status >= 400) {
            $error = $xml && isset($xml->Error) ? trim($xml->Error->Code . ' ' . $xml->Error->Message) : substr(strip_tags($raw), 0, 200);
            $this->fail($status, $error);
        }
        if (!$xml) {
            $this->fail($status, '响应无法解析');
        }
        return $xml;
    }

    public function authorization($method, $path, $queryString, array $headers, $body, $amzDate)
    {
        $date = substr($amzDate, 0, 8);
        $scope = "{$date}/us-east-1/route53/aws4_request";

        $canonical = [];
        foreach ($headers as $key => $value) {
            $canonical[strtolower($key)] = trim(preg_replace('/\s+/', ' ', (string) $value));
        }
        ksort($canonical);
        $signedHeaders = implode(';', array_keys($canonical));
        $canonicalHeaders = '';
        foreach ($canonical as $key => $value) {
            $canonicalHeaders .= "{$key}:{$value}\n";
        }

        $canonicalUri = implode('/', array_map('rawurlencode', explode('/', $path)));
        $canonicalRequest = implode("\n", [$method, $canonicalUri, $queryString, $canonicalHeaders, $signedHeaders, hash('sha256', (string) $body)]);
        $stringToSign = "AWS4-HMAC-SHA256\n{$amzDate}\n{$scope}\n" . hash('sha256', $canonicalRequest);

        $key = hash_hmac('sha256', $date, 'AWS4' . trim((string) ($this->config['secret_access_key'] ?? '')), true);
        $key = hash_hmac('sha256', 'us-east-1', $key, true);
        $key = hash_hmac('sha256', 'route53', $key, true);
        $key = hash_hmac('sha256', 'aws4_request', $key, true);
        $signature = hash_hmac('sha256', $stringToSign, $key);

        return 'AWS4-HMAC-SHA256 Credential=' . trim((string) ($this->config['access_key_id'] ?? '')) . "/{$scope}, SignedHeaders={$signedHeaders}, Signature={$signature}";
    }

    private static function canonicalQuery(array $query)
    {
        ksort($query, SORT_STRING);
        $pairs = [];
        foreach ($query as $key => $value) {
            $pairs[] = rawurlencode((string) $key) . '=' . rawurlencode((string) $value);
        }
        return implode('&', $pairs);
    }
}
