<?php

class DigitalOceanDnsProvider extends DnsProvider
{
    const API = 'https://api.digitalocean.com/v2';

    public static function id()
    {
        return 'digitalocean';
    }

    public static function label()
    {
        return 'DigitalOcean';
    }

    public static function defaultTtl()
    {
        return 300;
    }

    public static function fields()
    {
        return [
            ['key' => 'token', 'label' => 'Personal Access Token', 'type' => 'secret', 'required' => true, 'placeholder' => 'dop_v1_…']
        ];
    }

    public static function permissionHint()
    {
        return '在 DigitalOcean「API → Tokens」创建 Token，自定义权限至少勾选 domain 的 read、create、update、delete。';
    }

    protected function fetchZones()
    {
        $zones = [];
        $page = 1;
        do {
            $data = $this->api('GET', '/domains?per_page=200&page=' . $page);
            foreach ($data['domains'] ?? [] as $domain) {
                $zones[] = ['id' => $domain['name'], 'name' => $domain['name']];
            }
            $page++;
        } while (!empty($data['links']['pages']['next']));
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $query = 'type=A&per_page=200';
        if ($name !== null) {
            $query .= '&name=' . rawurlencode(self::normalizeName($name));
        }

        $records = [];
        $page = 1;
        do {
            $data = $this->api('GET', '/domains/' . rawurlencode($zone['name']) . '/records?' . $query . '&page=' . $page);
            foreach ($data['domain_records'] ?? [] as $record) {
                if (($record['type'] ?? '') !== 'A') {
                    continue;
                }
                $records[] = [
                    'id' => (string) $record['id'],
                    'name' => self::absoluteName($record['name'], $zone['name']),
                    'values' => [trim((string) $record['data'])],
                    'ttl' => (int) ($record['ttl'] ?? 300),
                    'raw' => $record
                ];
            }
            $page++;
        } while (!empty($data['links']['pages']['next']));

        return self::filterRecords($records, $name, $ip);
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->api('POST', '/domains/' . rawurlencode($zone['name']) . '/records', [
            'type' => 'A',
            'name' => self::relativeName($name, $zone['name']),
            'data' => $ip,
            'ttl' => $this->ttl()
        ]);
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $this->api('PUT', '/domains/' . rawurlencode($zone['name']) . '/records/' . rawurlencode($record['id']), [
            'type' => 'A',
            'name' => $record['raw']['name'],
            'data' => $values[0],
            'ttl' => $record['ttl']
        ]);
    }

    public function deleteARecord(array $zone, array $record)
    {
        $this->api('DELETE', '/domains/' . rawurlencode($zone['name']) . '/records/' . rawurlencode($record['id']));
    }

    private function api($method, $path, array $payload = null)
    {
        [$status, $data] = $this->requestJson($method, self::API . $path, [
            'Authorization' => 'Bearer ' . trim((string) ($this->config['token'] ?? ''))
        ], $payload);

        if ($status >= 400) {
            $this->fail($status, trim(($data['id'] ?? '') . ' ' . ($data['message'] ?? '')));
        }
        return $data;
    }
}
