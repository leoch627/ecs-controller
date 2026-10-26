<?php

require_once __DIR__ . '/dns/DnsProviderRegistry.php';

/**
 * 域名解析服务。具体服务商见 dns/ 目录，这里只放与服务商无关的逻辑：
 * 1. 自动解析 (DDNS)：按"账号备注[-实例].根域名"维护 A 记录。
 * 2. 失效清理：实例过期、被释放或回收后，把指向该 IP 的 A 记录删掉（多值记录只移除这个 IP）。
 */
class DdnsService
{
    private $config;
    private $provider;

    /**
     * @param array $config 全部设置（密钥已解密）
     * @param DnsProvider|null $provider 测试时可直接注入
     */
    public function __construct(array $config, DnsProvider $provider = null)
    {
        $this->config = $config;
        $this->provider = $provider ?: DnsProviderRegistry::create($config['ddns_provider'] ?? 'cloudflare', $config);
    }

    public function getProvider()
    {
        return $this->provider::id();
    }

    public function getProviderLabel()
    {
        return $this->provider::label();
    }

    public function hasCredentials()
    {
        return $this->provider->isConfigured();
    }

    /**
     * 自动解析是否可用：开关已开、服务商凭据和根域名齐全。
     */
    public function isEnabled()
    {
        return ($this->config['ddns_enabled'] ?? '0') === '1'
            && $this->hasCredentials()
            && $this->domain() !== '';
    }

    /**
     * 失效清理是否可用。未填根域名时扫描服务商账号下的全部域名。
     */
    public function isCleanupEnabled()
    {
        return ($this->config['dns_cleanup_enabled'] ?? '0') === '1' && $this->hasCredentials();
    }

    public function describeCleanupScope()
    {
        if ($this->provider->configuredZone()) {
            return '指定 Zone 下的全部 A 记录';
        }
        $domain = $this->domain();
        return $domain !== '' ? "{$domain} 下的全部 A 记录" : $this->getProviderLabel() . ' 账号下全部域名的 A 记录';
    }

    public function buildRecordName(array $account, $sameGroupInstanceCount = 1)
    {
        $domain = $this->domain();
        if ($domain === '') {
            throw new Exception('请先填写 DDNS 根域名');
        }

        $accountSlug = $this->slug($account['account_remark'] ?? $account['remark'] ?? '');
        $instanceSlug = $this->slug($account['instance_name'] ?? '');
        $instanceId = trim((string) ($account['instance_id'] ?? ''));
        $shortId = $this->slug($instanceId !== '' ? preg_replace('/^i-/', '', $instanceId) : '');

        if ($accountSlug === '') {
            $accountSlug = $instanceSlug ?: $shortId;
        }
        if ($accountSlug === '') {
            throw new Exception('DDNS 记录名生成失败，请检查账号备注或实例名称');
        }

        $subdomain = $accountSlug;
        if ((int) $sameGroupInstanceCount > 1) {
            $suffix = $instanceSlug ?: $shortId;
            if ($suffix !== '' && $suffix !== $accountSlug) {
                $subdomain .= '-' . $suffix;
            }
        }

        $subdomain = trim($subdomain, '-');
        return $subdomain . '.' . $domain;
    }

    public function syncARecord($recordName, $ip)
    {
        if (!$this->isEnabled()) {
            return ['success' => true, 'skipped' => true, 'message' => 'DDNS 未启用'];
        }

        $recordName = DnsProvider::normalizeName($recordName);
        $ip = trim((string) $ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return ['success' => false, 'message' => '公网 IP 为空或不是公网 IPv4'];
        }

        $zone = $this->zoneFor($recordName);
        $records = $this->provider->listARecords($zone, $recordName);
        foreach ($records as $record) {
            if ($this->provider->recordMatches($record, $ip)) {
                return ['success' => true, 'skipped' => true, 'record' => $recordName, 'ip' => $ip, 'action' => 'unchanged'];
            }
        }

        if (!empty($records)) {
            $this->provider->updateARecord($zone, $records[0], [$ip]);
            return ['success' => true, 'record' => $recordName, 'ip' => $ip, 'action' => 'updated'];
        }

        $this->provider->createARecord($zone, $recordName, $ip);
        return ['success' => true, 'record' => $recordName, 'ip' => $ip, 'action' => 'created'];
    }

    public function deleteARecord($recordName)
    {
        if (!$this->isEnabled()) {
            return ['success' => true, 'skipped' => true, 'message' => 'DDNS 未启用'];
        }

        $recordName = DnsProvider::normalizeName($recordName);
        if ($recordName === '') {
            return ['success' => false, 'message' => 'DDNS 记录名为空'];
        }

        $zone = $this->zoneFor($recordName);
        $records = $this->provider->listARecords($zone, $recordName);
        if (empty($records)) {
            return ['success' => true, 'skipped' => true, 'record' => $recordName, 'message' => '记录不存在'];
        }
        foreach ($records as $record) {
            $this->provider->deleteARecord($zone, $record);
        }
        return ['success' => true, 'record' => $recordName, 'action' => 'deleted'];
    }

    /**
     * 从解析中移除某个 IP：只含该 IP 的记录直接删除，多值记录只去掉这个 IP。
     * 返回 ['success' => bool, 'changes' => [['record' => name, 'action' => deleted|updated]], 'message' => ...]
     */
    public function removeIpFromRecords($ip)
    {
        $ip = trim((string) $ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ['success' => false, 'changes' => [], 'message' => 'IP 地址无效'];
        }
        if (!$this->hasCredentials()) {
            return ['success' => false, 'changes' => [], 'message' => '域名解析服务商凭据未配置'];
        }

        $changes = [];
        foreach ($this->scopeZones() as $zone) {
            foreach ($this->provider->listARecords($zone, null, $ip) as $record) {
                $remaining = array_values(array_filter($record['values'], function ($value) use ($ip) {
                    return $value !== $ip;
                }));
                if (empty($remaining)) {
                    $this->provider->deleteARecord($zone, $record);
                    $changes[] = ['record' => $record['name'], 'action' => 'deleted'];
                } else {
                    $this->provider->updateARecord($zone, $record, $remaining);
                    $changes[] = ['record' => $record['name'], 'action' => 'updated', 'remaining' => count($remaining)];
                }
            }
        }

        return [
            'success' => true,
            'changes' => $changes,
            'message' => empty($changes) ? '解析中没有指向该 IP 的 A 记录' : $this->summarizeChanges($changes)
        ];
    }

    /**
     * 用当前（未保存的）配置测试服务商连通性，返回可读的检测结果。
     */
    public function testConnection()
    {
        $label = $this->getProviderLabel();
        if (!$this->hasCredentials()) {
            throw new Exception("请先填写 {$label} 的凭据");
        }

        $zones = $this->scopeZones();
        if ($this->provider->configuredZone() || $this->domain() !== '') {
            $zone = $zones[0];
            $count = count($this->provider->listARecords($zone));
            $name = $zone['name'] ?: $zone['id'];
            return [
                'success' => true,
                'message' => "{$label} 鉴权通过，已找到域名 {$name}，当前有 {$count} 条 A 记录。",
                'zones' => [$name]
            ];
        }

        $names = array_map(function ($zone) {
            return $zone['name'];
        }, $zones);
        return [
            'success' => true,
            'message' => "{$label} 鉴权通过，账号下共有 " . count($zones) . ' 个域名' . (empty($names) ? '' : '：' . implode('、', array_slice($names, 0, 5)) . (count($names) > 5 ? ' 等' : '')) . '。未填写根域名时，失效清理会处理全部域名。',
            'zones' => $names
        ];
    }

    private function domain()
    {
        $domain = strtolower(trim((string) ($this->config['ddns_domain'] ?? '')));
        $domain = preg_replace('#^https?://#', '', $domain);
        return trim(explode('/', $domain)[0] ?? '', '.');
    }

    private function configuredZone()
    {
        $zone = $this->provider->configuredZone();
        if ($zone && $zone['name'] === '') {
            $zone['name'] = $this->domain();
        }
        return $zone;
    }

    /** 自动解析的记录所在 Zone：优先用配置的 Zone ID，否则按根域名查找 */
    private function zoneFor($recordName)
    {
        $configured = $this->configuredZone();
        if ($configured) {
            return $configured;
        }

        $lookup = $this->domain() !== '' ? $this->domain() : $recordName;
        $zone = $this->provider->findZone($lookup);
        if (!$zone) {
            throw new Exception($this->getProviderLabel() . " 账号下没有找到域名 {$lookup}，请确认域名托管在这家服务商，且凭据有解析权限");
        }
        return $zone;
    }

    /** 失效清理 / 测试的范围：指定 Zone、根域名所在 Zone，或账号下全部域名 */
    private function scopeZones()
    {
        $configured = $this->configuredZone();
        if ($configured) {
            return [$configured];
        }
        if ($this->domain() !== '') {
            return [$this->zoneFor($this->domain())];
        }
        return $this->provider->listZones();
    }

    private function summarizeChanges(array $changes)
    {
        $parts = [];
        foreach ($changes as $change) {
            $parts[] = $change['action'] === 'deleted'
                ? "已删除 {$change['record']}"
                : "已从 {$change['record']} 移除（剩余 {$change['remaining']} 个 IP）";
        }
        return implode('；', $parts);
    }

    private function slug($value)
    {
        $original = trim((string) $value);
        $value = strtolower($original);
        if ($value === '') {
            return '';
        }

        if (function_exists('iconv')) {
            $converted = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $value);
            if ($converted !== false) {
                $value = $converted;
            }
        }

        $value = preg_replace('/[^a-z0-9]+/', '-', $value);
        $value = trim($value, '-');
        if ($value === '') {
            $value = substr(sha1($original), 0, 8);
        }
        return substr($value, 0, 48);
    }
}
