<?php

class CloudflareDnsProvider extends DnsProvider
{
    const API = 'https://api.cloudflare.com/client/v4';

    public static function id()
    {
        return 'cloudflare';
    }

    public static function label()
    {
        return 'Cloudflare';
    }

    public static function settingPrefix()
    {
        return 'cf';
    }

    public static function defaultTtl()
    {
        return 1; // 1 = Cloudflare 自动
    }

    public static function fields()
    {
        return [
            ['key' => 'token', 'label' => 'API Token', 'type' => 'secret', 'required' => true, 'placeholder' => '需要 Zone · DNS · Edit 权限'],
            ['key' => 'zone_id', 'label' => 'Zone ID', 'type' => 'text', 'placeholder' => '留空自动查询'],
            ['key' => 'proxied', 'label' => '自动解析的记录经过 Cloudflare 代理（橙色云朵）', 'type' => 'switch', 'hint' => '只代理 HTTP/HTTPS，开启后 SSH 等端口无法通过域名直连。']
        ];
    }

    public static function permissionHint()
    {
        return '在 Cloudflare「My Profile → API Tokens」创建 Token，权限选 Zone · DNS · Edit 和 Zone · Zone · Read，资源选要管理的域名。';
    }

    protected function fetchZones()
    {
        $zones = [];
        $page = 1;
        do {
            $data = $this->api('GET', '/zones?per_page=50&page=' . $page);
            foreach ($data['result'] ?? [] as $zone) {
                $zones[] = ['id' => $zone['id'], 'name' => $zone['name']];
            }
            $totalPages = (int) ($data['result_info']['total_pages'] ?? 1);
            $page++;
        } while ($page <= $totalPages);
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $query = 'type=A&per_page=100';
        if ($name !== null) {
            $query .= '&name=' . rawurlencode(self::normalizeName($name));
        }
        if ($ip !== null) {
            $query .= '&content=' . rawurlencode($ip);
        }

        $records = [];
        $page = 1;
        do {
            $data = $this->api('GET', '/zones/' . rawurlencode($zone['id']) . '/dns_records?' . $query . '&page=' . $page);
            foreach ($data['result'] ?? [] as $record) {
                $records[] = [
                    'id' => $record['id'],
                    'name' => self::normalizeName($record['name']),
                    'values' => [trim((string) $record['content'])],
                    'ttl' => (int) ($record['ttl'] ?? 1),
                    'raw' => $record
                ];
            }
            $totalPages = (int) ($data['result_info']['total_pages'] ?? 1);
            $page++;
        } while ($page <= $totalPages);

        return self::filterRecords($records, $name, $ip);
    }

    public function recordMatches(array $record, $ip)
    {
        return parent::recordMatches($record, $ip) && (bool) ($record['raw']['proxied'] ?? false) === $this->proxied();
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->api('POST', '/zones/' . rawurlencode($zone['id']) . '/dns_records', [
            'type' => 'A',
            'name' => self::normalizeName($name),
            'content' => $ip,
            'ttl' => 1,
            'proxied' => $this->proxied(),
            'comment' => 'Managed by ecs-controller'
        ]);
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $this->api('PATCH', '/zones/' . rawurlencode($zone['id']) . '/dns_records/' . rawurlencode($record['id']), [
            'content' => $values[0],
            'proxied' => $this->proxied()
        ]);
    }

    public function deleteARecord(array $zone, array $record)
    {
        $this->api('DELETE', '/zones/' . rawurlencode($zone['id']) . '/dns_records/' . rawurlencode($record['id']));
    }

    private function proxied()
    {
        return !empty($this->config['proxied']) && $this->config['proxied'] !== '0';
    }

    private function api($method, $path, array $payload = null)
    {
        [$status, $data] = $this->requestJson($method, self::API . $path, [
            'Authorization' => 'Bearer ' . trim((string) ($this->config['token'] ?? ''))
        ], $payload);

        if (empty($data['success'])) {
            $messages = array_map(function ($error) {
                return trim(($error['code'] ?? '') . ' ' . ($error['message'] ?? ''));
            }, $data['errors'] ?? []);
            $this->fail($status, implode('；', $messages));
        }
        return $data;
    }
}
