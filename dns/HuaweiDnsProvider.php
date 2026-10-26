<?php

/**
 * 华为云 云解析服务。AK/SK 按 APIG "SDK-HMAC-SHA256" 规则签名，与官方 SDK 的签名实现逐字节一致。
 * 公网域名是全局资源，任意区域的终端节点都能访问。
 */
class HuaweiDnsProvider extends DnsProvider
{
    public static function id()
    {
        return 'huawei';
    }

    public static function label()
    {
        return '华为云';
    }

    public static function market()
    {
        return 'cn';
    }

    public static function settingPrefix()
    {
        return 'hw';
    }

    public static function defaultTtl()
    {
        return 300;
    }

    public static function fields()
    {
        return [
            ['key' => 'ak', 'label' => 'Access Key ID', 'type' => 'text', 'required' => true, 'placeholder' => '华为云 AK'],
            ['key' => 'sk', 'label' => 'Secret Access Key', 'type' => 'secret', 'required' => true, 'placeholder' => '华为云 SK'],
            ['key' => 'region', 'label' => '接入点', 'type' => 'select', 'default' => 'cn-north-4', 'hint' => '公网解析是全局服务，中国站选北京四，国际站选香港即可。', 'options' => [
                ['value' => 'cn-north-4', 'label' => '中国站 · 华北-北京四'],
                ['value' => 'cn-east-3', 'label' => '中国站 · 华东-上海一'],
                ['value' => 'cn-south-1', 'label' => '中国站 · 华南-广州'],
                ['value' => 'ap-southeast-1', 'label' => '国际站 · 中国-香港'],
                ['value' => 'ap-southeast-3', 'label' => '国际站 · 亚太-新加坡']
            ]],
            ['key' => 'zone_id', 'label' => 'Zone ID', 'type' => 'text', 'placeholder' => '留空自动查询']
        ];
    }

    public static function permissionHint()
    {
        return '在华为云 IAM 为该 AK 授予 DNS FullAccess，或自定义策略包含 dns:zone:list、dns:recordset:list、dns:recordset:create、dns:recordset:update、dns:recordset:delete。';
    }

    protected function fetchZones()
    {
        $zones = [];
        $offset = 0;
        do {
            $data = $this->api('GET', '/v2/zones', ['type' => 'public', 'limit' => 500, 'offset' => $offset]);
            $page = $data['zones'] ?? [];
            foreach ($page as $zone) {
                $zones[] = ['id' => $zone['id'], 'name' => $zone['name']];
            }
            $offset += count($page);
            $total = (int) ($data['metadata']['total_count'] ?? $offset);
        } while (!empty($page) && $offset < $total);
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $query = ['zone_type' => 'public', 'type' => 'A', 'zone_id' => $zone['id'], 'limit' => 500];
        if ($name !== null) {
            $query['name'] = self::normalizeName($name) . '.';
            $query['search_mode'] = 'equal';
        }
        if ($ip !== null) {
            $query['records'] = $ip;
        }

        $records = [];
        $offset = 0;
        do {
            $query['offset'] = $offset;
            $data = $this->api('GET', '/v2.1/recordsets', $query);
            $page = $data['recordsets'] ?? [];
            foreach ($page as $recordSet) {
                // default = true 是系统生成的 NS/SOA，不能改也不能删
                if (!empty($recordSet['default'])) {
                    continue;
                }
                $records[] = [
                    'id' => $recordSet['id'],
                    'name' => self::normalizeName($recordSet['name']),
                    'values' => array_values(array_map('trim', $recordSet['records'] ?? [])),
                    'ttl' => (int) ($recordSet['ttl'] ?? 300),
                    'raw' => $recordSet
                ];
            }
            $offset += count($page);
            $total = (int) ($data['metadata']['total_count'] ?? $offset);
        } while (!empty($page) && $offset < $total);

        return self::filterRecords($records, $name, $ip);
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->api('POST', '/v2.1/zones/' . rawurlencode($zone['id']) . '/recordsets', [], [
            'name' => self::normalizeName($name) . '.',
            'type' => 'A',
            'ttl' => $this->ttl(),
            'records' => [$ip],
            'description' => 'Managed by ecs-controller'
        ]);
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $zoneId = $record['raw']['zone_id'] ?? $zone['id'];
        $this->api('PUT', '/v2.1/zones/' . rawurlencode($zoneId) . '/recordsets/' . rawurlencode($record['id']), [], [
            'name' => $record['name'] . '.',
            'type' => 'A',
            'ttl' => $record['ttl'],
            'records' => array_values($values)
        ]);
    }

    public function deleteARecord(array $zone, array $record)
    {
        $zoneId = $record['raw']['zone_id'] ?? $zone['id'];
        $this->api('DELETE', '/v2.1/zones/' . rawurlencode($zoneId) . '/recordsets/' . rawurlencode($record['id']));
    }

    private function endpoint()
    {
        $region = preg_replace('/[^a-z0-9-]/', '', strtolower(trim((string) ($this->config['region'] ?? '')))) ?: 'cn-north-4';
        return 'dns.' . $region . '.myhuaweicloud.com';
    }

    private function api($method, $path, array $query = [], array $payload = null)
    {
        $body = $payload === null ? '' : json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $queryString = self::canonicalQueryString($query);
        $sdkDate = gmdate('Ymd\THis\Z');
        $url = 'https://' . $this->endpoint() . $path . ($queryString !== '' ? '?' . $queryString : '');

        [$status, $raw] = $this->request($method, $url, [
            'Content-Type' => 'application/json',
            'X-Sdk-Date' => $sdkDate,
            'Authorization' => $this->authorization($method, $path, $queryString, $body, $sdkDate)
        ], $body);

        $decoded = $raw === '' ? [] : json_decode($raw, true);
        if ($status >= 400) {
            $detail = is_array($decoded)
                ? trim(($decoded['code'] ?? $decoded['error_code'] ?? '') . ' ' . ($decoded['message'] ?? $decoded['error_msg'] ?? ''))
                : '';
            $this->fail($status, $detail ?: substr(strip_tags($raw), 0, 200));
        }
        if ($raw !== '' && !is_array($decoded)) {
            $this->fail($status, '响应无法解析');
        }
        return is_array($decoded) ? $decoded : [];
    }

    private function authorization($method, $path, $queryString, $body, $sdkDate)
    {
        $headers = [
            'content-type' => 'application/json',
            'host' => $this->endpoint(),
            'x-sdk-date' => $sdkDate
        ];
        ksort($headers);
        $signedHeaders = implode(';', array_keys($headers));
        $canonicalHeaders = '';
        foreach ($headers as $key => $value) {
            $canonicalHeaders .= $key . ':' . trim($value) . "\n";
        }

        $segments = array_map('rawurlencode', explode('/', rawurldecode($path)));
        $canonicalUri = implode('/', $segments);
        if (substr($canonicalUri, -1) !== '/') {
            $canonicalUri .= '/';
        }

        $canonicalRequest = implode("\n", [
            strtoupper($method),
            $canonicalUri,
            $queryString,
            $canonicalHeaders,
            $signedHeaders,
            hash('sha256', $body)
        ]);
        $stringToSign = "SDK-HMAC-SHA256\n{$sdkDate}\n" . hash('sha256', $canonicalRequest);
        $signature = hash_hmac('sha256', $stringToSign, trim((string) ($this->config['sk'] ?? '')));

        return 'SDK-HMAC-SHA256 Access=' . trim((string) ($this->config['ak'] ?? '')) . ', SignedHeaders=' . $signedHeaders . ', Signature=' . $signature;
    }

    private static function canonicalQueryString(array $query)
    {
        ksort($query, SORT_STRING);
        $pairs = [];
        foreach ($query as $key => $value) {
            $pairs[] = rawurlencode((string) $key) . '=' . rawurlencode(is_bool($value) ? ($value ? 'true' : 'false') : (string) $value);
        }
        return implode('&', $pairs);
    }
}
