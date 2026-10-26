<?php

/**
 * 腾讯云 DNSPod（云 API 3.0，版本 2021-03-23），TC3-HMAC-SHA256 签名。
 */
class DnspodDnsProvider extends DnsProvider
{
    const SERVICE = 'dnspod';
    const VERSION = '2021-03-23';

    public static function id()
    {
        return 'dnspod';
    }

    public static function label()
    {
        return '腾讯云 DNSPod';
    }

    public static function market()
    {
        return 'cn';
    }

    public static function fields()
    {
        return [
            ['key' => 'secret_id', 'label' => 'SecretId', 'type' => 'text', 'required' => true, 'placeholder' => 'AKID…'],
            ['key' => 'secret_key', 'label' => 'SecretKey', 'type' => 'secret', 'required' => true],
            ['key' => 'endpoint', 'label' => '接入点', 'type' => 'select', 'default' => 'dnspod.tencentcloudapi.com', 'options' => [
                ['value' => 'dnspod.tencentcloudapi.com', 'label' => '腾讯云中国站'],
                ['value' => 'dnspod.intl.tencentcloudapi.com', 'label' => '腾讯云国际站']
            ]]
        ];
    }

    public static function permissionHint()
    {
        return '使用腾讯云「访问管理 → API 密钥」的 SecretId / SecretKey（不是旧版 DNSPod Token），子用户需要 QcloudDNSPodFullAccess。免费套餐 TTL 最低 600 秒。';
    }

    protected function fetchZones()
    {
        $zones = [];
        $offset = 0;
        do {
            $data = $this->call('DescribeDomainList', ['Offset' => $offset, 'Limit' => 3000]);
            $page = $data['DomainList'] ?? [];
            foreach ($page as $domain) {
                $zones[] = ['id' => $domain['Name'], 'name' => $domain['Name']];
            }
            $offset += count($page);
            $total = (int) ($data['DomainCountInfo']['AllTotal'] ?? $data['DomainCountInfo']['DomainTotal'] ?? $offset);
        } while (!empty($page) && $offset < $total);
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $params = ['Domain' => $zone['name'], 'RecordType' => 'A', 'Limit' => 3000, 'ErrorOnEmpty' => 'no'];
        if ($name !== null) {
            $params['Subdomain'] = self::relativeName($name, $zone['name']);
        }
        if ($ip !== null) {
            $params['Keyword'] = $ip;
        }

        $records = [];
        $offset = 0;
        do {
            $params['Offset'] = $offset;
            $data = $this->call('DescribeRecordList', $params, ['ResourceNotFound.NoDataOfRecord']);
            $page = $data['RecordList'] ?? [];
            foreach ($page as $record) {
                if (($record['Type'] ?? '') !== 'A') {
                    continue;
                }
                $records[] = [
                    'id' => (string) $record['RecordId'],
                    'name' => self::absoluteName($record['Name'], $zone['name']),
                    'values' => [trim((string) $record['Value'])],
                    'ttl' => (int) ($record['TTL'] ?? 600),
                    'raw' => $record
                ];
            }
            $offset += count($page);
            $total = (int) ($data['RecordCountInfo']['TotalCount'] ?? $offset);
        } while (!empty($page) && $offset < $total);

        return self::filterRecords($records, $name, $ip);
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->call('CreateRecord', [
            'Domain' => $zone['name'],
            'SubDomain' => self::relativeName($name, $zone['name']),
            'RecordType' => 'A',
            'RecordLine' => '默认',
            'Value' => $ip,
            'TTL' => $this->ttl()
        ]);
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $params = [
            'Domain' => $zone['name'],
            'RecordId' => (int) $record['id'],
            'SubDomain' => $record['raw']['Name'],
            'RecordType' => 'A',
            'RecordLine' => $record['raw']['Line'] ?? '默认',
            'Value' => $values[0],
            'TTL' => $record['ttl']
        ];
        if (!empty($record['raw']['LineId'])) {
            $params['RecordLineId'] = $record['raw']['LineId'];
        }
        $this->call('ModifyRecord', $params);
    }

    public function deleteARecord(array $zone, array $record)
    {
        $this->call('DeleteRecord', ['Domain' => $zone['name'], 'RecordId' => (int) $record['id']]);
    }

    private function host()
    {
        $host = trim((string) ($this->config['endpoint'] ?? ''));
        return in_array($host, ['dnspod.tencentcloudapi.com', 'dnspod.intl.tencentcloudapi.com'], true) ? $host : 'dnspod.tencentcloudapi.com';
    }

    /**
     * @param array $emptyCodes 视为"没有数据"而不是报错的错误码
     */
    private function call($action, array $params, array $emptyCodes = [])
    {
        $payload = json_encode($params, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $timestamp = time();
        $host = $this->host();

        [$status, $raw] = $this->request('POST', 'https://' . $host . '/', [
            'Authorization' => $this->authorization($host, $payload, $timestamp),
            'Content-Type' => 'application/json; charset=utf-8',
            'Host' => $host,
            'X-TC-Action' => $action,
            'X-TC-Timestamp' => (string) $timestamp,
            'X-TC-Version' => self::VERSION
        ], $payload);

        $decoded = json_decode($raw, true);
        $response = is_array($decoded) ? ($decoded['Response'] ?? null) : null;
        if (!is_array($response)) {
            $this->fail($status, '响应无法解析');
        }
        if (!empty($response['Error'])) {
            if (in_array($response['Error']['Code'] ?? '', $emptyCodes, true)) {
                return [];
            }
            $code = $response['Error']['Code'] ?? '';
            $status = strpos($code, 'AuthFailure') === 0 ? 401 : (strpos($code, 'UnauthorizedOperation') === 0 ? 403 : $status);
            $this->fail($status === 200 ? 0 : $status, trim($code . ' ' . ($response['Error']['Message'] ?? '')));
        }
        return $response;
    }

    public function authorization($host, $payload, $timestamp)
    {
        $secretId = trim((string) ($this->config['secret_id'] ?? ''));
        $secretKey = trim((string) ($this->config['secret_key'] ?? ''));
        $date = gmdate('Y-m-d', $timestamp);

        $canonicalRequest = "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:{$host}\n\ncontent-type;host\n" . hash('sha256', $payload);
        $scope = "{$date}/" . self::SERVICE . '/tc3_request';
        $stringToSign = "TC3-HMAC-SHA256\n{$timestamp}\n{$scope}\n" . hash('sha256', $canonicalRequest);

        $secretDate = hash_hmac('sha256', $date, 'TC3' . $secretKey, true);
        $secretService = hash_hmac('sha256', self::SERVICE, $secretDate, true);
        $secretSigning = hash_hmac('sha256', 'tc3_request', $secretService, true);
        $signature = hash_hmac('sha256', $stringToSign, $secretSigning);

        return "TC3-HMAC-SHA256 Credential={$secretId}/{$scope}, SignedHeaders=content-type;host, Signature={$signature}";
    }
}
