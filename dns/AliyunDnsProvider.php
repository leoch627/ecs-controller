<?php

use AlibabaCloud\Client\AlibabaCloud;
use AlibabaCloud\Client\Exception\ClientException;
use AlibabaCloud\Client\Exception\ServerException;

/**
 * 阿里云 云解析 DNS（Alidns 2015-01-09）。复用项目里已有的阿里云 SDK 完成签名。
 */
class AliyunDnsProvider extends DnsProvider
{
    const CLIENT_NAME = 'ecs-controller-alidns';

    public static function id()
    {
        return 'aliyun';
    }

    public static function label()
    {
        return '阿里云';
    }

    public static function market()
    {
        return 'cn';
    }

    public static function fields()
    {
        return [
            ['key' => 'access_key_id', 'label' => 'AccessKey ID', 'type' => 'text', 'required' => true, 'placeholder' => 'LTAI…'],
            ['key' => 'access_key_secret', 'label' => 'AccessKey Secret', 'type' => 'secret', 'required' => true],
            ['key' => 'endpoint', 'label' => '接入点', 'type' => 'select', 'default' => 'alidns.aliyuncs.com', 'options' => [
                ['value' => 'alidns.aliyuncs.com', 'label' => '中国站 · alidns.aliyuncs.com'],
                ['value' => 'alidns.ap-southeast-1.aliyuncs.com', 'label' => '国际站 · alidns.ap-southeast-1.aliyuncs.com']
            ]]
        ];
    }

    public static function permissionHint()
    {
        return '建议单独建一个 RAM 用户，授予 AliyunDNSFullAccess；也可以直接用 ECS 账号的 AK，前提是它有云解析权限。免费版解析的 TTL 最低 600 秒。';
    }

    protected function fetchZones()
    {
        $zones = [];
        $page = 1;
        do {
            $data = $this->call('DescribeDomains', ['PageNumber' => $page, 'PageSize' => 100]);
            foreach ($data['Domains']['Domain'] ?? [] as $domain) {
                $zones[] = ['id' => $domain['DomainName'], 'name' => $domain['DomainName']];
            }
            $total = (int) ($data['TotalCount'] ?? 0);
            $page++;
        } while (($page - 1) * 100 < $total);
        return $zones;
    }

    public function listARecords(array $zone, $name = null, $ip = null)
    {
        $params = ['DomainName' => $zone['name'], 'TypeKeyWord' => 'A', 'PageSize' => 500];
        if ($name !== null) {
            $params['RRKeyWord'] = self::relativeName($name, $zone['name']);
        }
        if ($ip !== null) {
            $params['ValueKeyWord'] = $ip;
        }

        $records = [];
        $page = 1;
        do {
            $params['PageNumber'] = $page;
            $data = $this->call('DescribeDomainRecords', $params);
            foreach ($data['DomainRecords']['Record'] ?? [] as $record) {
                if (($record['Type'] ?? '') !== 'A') {
                    continue;
                }
                $records[] = [
                    'id' => (string) $record['RecordId'],
                    'name' => self::absoluteName($record['RR'], $zone['name']),
                    'values' => [trim((string) $record['Value'])],
                    'ttl' => (int) ($record['TTL'] ?? 600),
                    'raw' => $record
                ];
            }
            $total = (int) ($data['TotalCount'] ?? 0);
            $page++;
        } while (($page - 1) * 500 < $total);

        return self::filterRecords($records, $name, $ip);
    }

    public function createARecord(array $zone, $name, $ip)
    {
        $this->call('AddDomainRecord', [
            'DomainName' => $zone['name'],
            'RR' => self::relativeName($name, $zone['name']),
            'Type' => 'A',
            'Value' => $ip,
            'TTL' => $this->ttl()
        ]);
    }

    public function updateARecord(array $zone, array $record, array $values)
    {
        $params = [
            'RecordId' => $record['id'],
            'RR' => $record['raw']['RR'],
            'Type' => 'A',
            'Value' => $values[0],
            'TTL' => $record['ttl']
        ];
        if (!empty($record['raw']['Line'])) {
            $params['Line'] = $record['raw']['Line'];
        }
        $this->call('UpdateDomainRecord', $params);
    }

    public function deleteARecord(array $zone, array $record)
    {
        $this->call('DeleteDomainRecord', ['RecordId' => $record['id']]);
    }

    protected function call($action, array $params)
    {
        $endpoint = trim((string) ($this->config['endpoint'] ?? '')) ?: 'alidns.aliyuncs.com';
        try {
            // 用独立命名的客户端，避免覆盖 ECS 调用使用的默认客户端
            AlibabaCloud::accessKeyClient(
                trim((string) ($this->config['access_key_id'] ?? '')),
                trim((string) ($this->config['access_key_secret'] ?? ''))
            )->regionId('cn-hangzhou')->name(self::CLIENT_NAME);

            $result = AlibabaCloud::rpc()
                ->client(self::CLIENT_NAME)
                ->product('Alidns')
                ->scheme('https')
                ->version('2015-01-09')
                ->action($action)
                ->method('POST')
                ->host($endpoint)
                ->options([
                    'query' => $params,
                    'connect_timeout' => 10.0,
                    'timeout' => 20.0
                ])
                ->request();

            return $result->toArray();
        } catch (ServerException $e) {
            $status = $e->getResult() ? (int) $e->getResult()->getStatusCode() : 0;
            $this->fail($status, $e->getErrorCode() . ' ' . $e->getErrorMessage());
        } catch (ClientException $e) {
            $this->fail(0, $e->getErrorMessage() ?: $e->getMessage());
        }
    }
}
