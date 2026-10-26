<?php

/**
 * GoDaddy Domains API。同一主机名的 A 记录按"记录集"整体读写：PUT 覆盖、DELETE 全删。
 */
class GodaddyDnsProvider extends DnsProvider
{
    const API = 'https://api.godaddy.com/v1';

    public static function id()
    {
        return 'godaddy';
    }

    public static function label()
    {
        return 'GoDaddy';
    }

    public static function fields()
    {
        return [
            ['key' => 'api_key', 'label' => 'API Key', 'type' => 'text', 'required' => true],
            ['key' => 'api_secret', 'label' => 'API Secret', 'type' => 'secret', 'required' => true]
        ];
    }

    public static function permissionHint()
    {
        return '在 developer.godaddy.com/keys 创建 Production 环境的 Key。注意：GoDaddy 只对拥有 10 个以上域名或订阅了 Discount Domain Club 的账号开放 API，否则会返回 403。';
    }

    protected function fetchZones()
    {
        $data = $this->api('GET', '/domains?statuses=ACTIVE&limit=1000');
        $zones = [];
        foreach ($data as $domain) {
            $zones[] = ['id' => $domain['domain'], 'name' => $domain['domain']];
        }
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $path = '/domains/' . rawurlencode($zone['name']) . '/records/A';
        if ($name !== null) {
            $path .= '/' . rawurlencode(self::relativeName($name, $zone['name']));
        }

        $sets = [];
        foreach ($this->api('GET', $path) as $record) {
            $host = $record['name'] ?? '@';
            if (!isset($sets[$host])) {
                $sets[$host] = [
                    'id' => $host,
                    'name' => self::absoluteName($host, $zone['name']),
                    'values' => [],
                    'ttl' => (int) ($record['ttl'] ?? 600),
                    'raw' => ['host' => $host]
                ];
            }
            $sets[$host]['values'][] = trim((string) $record['data']);
        }
        return self::filterRecords(array_values($sets), $name, $ip);
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->put($zone, self::relativeName($name, $zone['name']), [$ip], $this->ttl());
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $this->put($zone, $record['raw']['host'], $values, max($record['ttl'], 600));
    }

    public function deleteARecord(array $zone, array $record)
    {
        $this->api('DELETE', '/domains/' . rawurlencode($zone['name']) . '/records/A/' . rawurlencode($record['raw']['host']));
    }

    private function put(array $zone, $host, array $values, $ttl)
    {
        $payload = array_map(function ($value) use ($ttl) {
            return ['data' => $value, 'ttl' => (int) $ttl];
        }, array_values($values));
        $this->api('PUT', '/domains/' . rawurlencode($zone['name']) . '/records/A/' . rawurlencode($host), $payload);
    }

    private function api($method, $path, array $payload = null)
    {
        [$status, $data] = $this->requestJson($method, self::API . $path, [
            'Authorization' => 'sso-key ' . trim((string) ($this->config['api_key'] ?? '')) . ':' . trim((string) ($this->config['api_secret'] ?? '')),
            'Accept' => 'application/json'
        ], $payload);

        if ($status >= 400) {
            $this->fail($status, trim(($data['code'] ?? '') . ' ' . ($data['message'] ?? '')));
        }
        return $data;
    }
}
