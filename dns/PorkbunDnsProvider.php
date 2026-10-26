<?php

/**
 * Porkbun API v3（POST JSON，status = SUCCESS 表示成功）。
 */
class PorkbunDnsProvider extends DnsProvider
{
    const API = 'https://api.porkbun.com/api/json/v3/';

    public static function id()
    {
        return 'porkbun';
    }

    public static function label()
    {
        return 'Porkbun';
    }

    public static function fields()
    {
        return [
            ['key' => 'api_key', 'label' => 'API Key', 'type' => 'secret', 'required' => true, 'placeholder' => 'pk1_…'],
            ['key' => 'secret_api_key', 'label' => 'Secret API Key', 'type' => 'secret', 'required' => true, 'placeholder' => 'sk1_…']
        ];
    }

    public static function permissionHint()
    {
        return '在 porkbun.com/account/api 创建密钥，并在域名管理里给要用的域名打开「API Access」，否则会提示无权限。';
    }

    protected function fetchZones()
    {
        $zones = [];
        $start = 0;
        do {
            $data = $this->call('domain/listAll', ['start' => $start, 'apiAccess' => 'yes']);
            $page = $data['domains'] ?? [];
            foreach ($page as $domain) {
                $zones[] = ['id' => $domain['domain'], 'name' => $domain['domain']];
            }
            $start += count($page);
        } while (count($page) >= 1000);
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $data = $this->call('dns/retrieve/' . rawurlencode($zone['name']));
        $records = [];
        foreach ($data['records'] ?? [] as $record) {
            if (($record['type'] ?? '') !== 'A') {
                continue;
            }
            $records[] = [
                'id' => (string) $record['id'],
                'name' => self::normalizeName($record['name']),
                'values' => [trim((string) $record['content'])],
                'ttl' => (int) ($record['ttl'] ?? 600),
                'raw' => $record
            ];
        }
        return self::filterRecords($records, $name, $ip);
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->call('dns/create/' . rawurlencode($zone['name']), [
            'name' => self::relativeName($name, $zone['name'], ''),
            'type' => 'A',
            'content' => $ip,
            'ttl' => $this->ttl()
        ]);
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $this->call('dns/edit/' . rawurlencode($zone['name']) . '/' . rawurlencode($record['id']), [
            'name' => self::relativeName($record['name'], $zone['name'], ''),
            'type' => 'A',
            'content' => $values[0],
            'ttl' => $record['ttl']
        ]);
    }

    public function deleteARecord(array $zone, array $record)
    {
        $this->call('dns/delete/' . rawurlencode($zone['name']) . '/' . rawurlencode($record['id']));
    }

    private function call($path, array $payload = [])
    {
        $payload = array_merge([
            'apikey' => trim((string) ($this->config['api_key'] ?? '')),
            'secretapikey' => trim((string) ($this->config['secret_api_key'] ?? ''))
        ], $payload);

        [$status, $data] = $this->requestJson('POST', self::API . $path, [], $payload);
        if (($data['status'] ?? '') !== 'SUCCESS') {
            $this->fail($status === 200 ? 0 : $status, trim(($data['code'] ?? '') . ' ' . ($data['message'] ?? '')));
        }
        return $data;
    }
}
