<?php

/**
 * NameSilo（GET + XML，reply.code 300 表示成功）。
 */
class NamesiloDnsProvider extends DnsProvider
{
    const API = 'https://www.namesilo.com/api/';

    public static function id()
    {
        return 'namesilo';
    }

    public static function label()
    {
        return 'NameSilo';
    }

    public static function defaultTtl()
    {
        return 3600; // NameSilo 最低 3600 秒
    }

    public static function fields()
    {
        return [
            ['key' => 'api_key', 'label' => 'API Key', 'type' => 'secret', 'required' => true, 'placeholder' => '在 Account → API Manager 生成']
        ];
    }

    public static function permissionHint()
    {
        return '在 NameSilo「Account → API Manager」生成 API Key，不要勾选只读；如果设置了 IP 白名单，记得把服务器 IP 加进去。NameSilo 的 TTL 最低 3600 秒，解析生效会慢一些。';
    }

    protected function fetchZones()
    {
        $reply = $this->call('listDomains');
        $zones = [];
        foreach ($reply->domains->domain ?? [] as $domain) {
            $name = trim((string) $domain);
            $zones[] = ['id' => $name, 'name' => $name];
        }
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $reply = $this->call('dnsListRecords', ['domain' => $zone['name']]);
        $records = [];
        foreach ($reply->resource_record ?? [] as $record) {
            if ((string) $record->type !== 'A') {
                continue;
            }
            $records[] = [
                'id' => (string) $record->record_id,
                'name' => self::normalizeName((string) $record->host),
                'values' => [trim((string) $record->value)],
                'ttl' => (int) $record->ttl,
                'raw' => []
            ];
        }
        return self::filterRecords($records, $name, $ip);
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->call('dnsAddRecord', [
            'domain' => $zone['name'],
            'rrtype' => 'A',
            'rrhost' => self::relativeName($name, $zone['name'], ''),
            'rrvalue' => $ip,
            'rrttl' => $this->ttl()
        ]);
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $this->call('dnsUpdateRecord', [
            'domain' => $zone['name'],
            'rrid' => $record['id'],
            'rrhost' => self::relativeName($record['name'], $zone['name'], ''),
            'rrvalue' => $values[0],
            'rrttl' => max($record['ttl'], $this->ttl())
        ]);
    }

    public function deleteARecord(array $zone, array $record)
    {
        $this->call('dnsDeleteRecord', ['domain' => $zone['name'], 'rrid' => $record['id']]);
    }

    private function call($operation, array $params = [])
    {
        $query = http_build_query(array_merge(
            ['version' => '1', 'type' => 'xml', 'key' => trim((string) ($this->config['api_key'] ?? ''))],
            $params
        ), '', '&', PHP_QUERY_RFC3986);

        [$status, $raw] = $this->request('GET', self::API . $operation . '?' . $query);

        $previous = libxml_use_internal_errors(true);
        $xml = simplexml_load_string($raw);
        libxml_use_internal_errors($previous);
        if (!$xml || !isset($xml->reply)) {
            $this->fail($status, '响应无法解析');
        }

        $code = (string) $xml->reply->code;
        if ($code !== '300') {
            $this->fail(0, "code {$code} " . (string) $xml->reply->detail);
        }
        return $xml->reply;
    }
}
