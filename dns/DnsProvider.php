<?php

/**
 * DNS 服务商基类。
 *
 * 每家服务商只需实现：列出域名、按名称/IP 列出 A 记录、新建、改值、删除。
 * 记录统一成 ['id', 'name' => 完整域名(小写、不带结尾点), 'values' => [IP...], 'ttl', 'raw' => 原始数据]。
 * 一条记录一个 IP 的服务商（Cloudflare、阿里云等）values 只有一个元素；
 * 记录集型的服务商（华为云、Route 53、GoDaddy）一条记录可以带多个 IP。
 */
abstract class DnsProvider
{
    protected $config;
    private $transport;
    private $zoneCache = null;

    /**
     * @param array $config 该服务商的配置（字段名见 fields()，密钥已解密）
     * @param callable|null $transport 测试用：function ($method, $url, array $headers, $body) => [status, body]
     */
    public function __construct(array $config, callable $transport = null)
    {
        $this->config = $config;
        $this->transport = $transport;
    }

    abstract public static function id();

    abstract public static function label();

    /**
     * 表单字段：key、label、type(text|secret|select|switch)、required、placeholder、hint、options、default
     */
    abstract public static function fields();

    /** 'cn' 国内 / 'global' 海外，用于界面分组 */
    public static function market()
    {
        return 'global';
    }

    public static function defaultTtl()
    {
        return 600;
    }

    /** 授权说明，显示在配置表单下方 */
    public static function permissionHint()
    {
        return '';
    }

    /** 保存配置用的前缀；老版本的 Cloudflare / 华为云沿用 cf / hw 以兼容已有配置 */
    public static function settingPrefix()
    {
        return static::id();
    }

    /** @return array [['id' => ..., 'name' => 'example.com'], ...] */
    abstract protected function fetchZones();

    /**
     * @param array $zone
     * @param string|null $name 只要这个完整域名的记录
     * @param string|null $ip 只要包含这个 IP 的记录
     */
    abstract public function listARecords(array $zone, $name = null, $ip = null);

    abstract public function createARecord(array $zone, $name, $ip);

    /** 把记录的值改成 $values（非空）。一条记录一个 IP 的服务商只会收到一个值。 */
    abstract public function updateARecord(array $zone, array $record, array $values);

    abstract public function deleteARecord(array $zone, array $record);

    public function isConfigured()
    {
        foreach (static::fields() as $field) {
            if (!empty($field['required']) && trim((string) ($this->config[$field['key']] ?? '')) === '') {
                return false;
            }
        }
        return true;
    }

    /** 记录是否已经是期望的样子（自动解析用来跳过无变化的更新） */
    public function recordMatches(array $record, $ip)
    {
        return array_values($record['values']) === [$ip];
    }

    public function listZones()
    {
        if ($this->zoneCache === null) {
            $this->zoneCache = array_map(function ($zone) {
                $zone['name'] = self::normalizeName($zone['name']);
                return $zone;
            }, $this->fetchZones());
        }
        return $this->zoneCache;
    }

    /** 配置里直接填了 Zone ID 时使用它 */
    public function configuredZone()
    {
        $zoneId = trim((string) ($this->config['zone_id'] ?? ''));
        return $zoneId === '' ? null : ['id' => $zoneId, 'name' => ''];
    }

    /**
     * 找到托管某个域名的 Zone。传入子域名时逐级向上找。
     */
    public function findZone($domain)
    {
        $domain = self::normalizeName($domain);
        $byName = [];
        foreach ($this->listZones() as $zone) {
            $byName[$zone['name']] = $zone;
        }

        $labels = explode('.', $domain);
        while (count($labels) >= 2) {
            $candidate = implode('.', $labels);
            if (isset($byName[$candidate])) {
                return $byName[$candidate];
            }
            array_shift($labels);
        }
        return null;
    }

    // ---------------- helpers ----------------

    public static function normalizeName($name)
    {
        return rtrim(strtolower(trim((string) $name)), '.');
    }

    /** 完整域名转成相对 Zone 的主机记录，根域名返回 $apex（不同服务商写法不同：'@' 或 ''） */
    protected static function relativeName($fqdn, $zoneName, $apex = '@')
    {
        $fqdn = self::normalizeName($fqdn);
        $zoneName = self::normalizeName($zoneName);
        if ($fqdn === $zoneName) {
            return $apex;
        }
        $suffix = '.' . $zoneName;
        if ($zoneName !== '' && substr($fqdn, -strlen($suffix)) === $suffix) {
            return substr($fqdn, 0, -strlen($suffix));
        }
        throw new Exception("记录 {$fqdn} 不属于域名 {$zoneName}");
    }

    /** 主机记录转完整域名 */
    protected static function absoluteName($host, $zoneName)
    {
        $host = trim((string) $host);
        if ($host === '' || $host === '@') {
            return self::normalizeName($zoneName);
        }
        return self::normalizeName($host . '.' . $zoneName);
    }

    /** 统一在客户端再做一次精确过滤，服务商的搜索参数多为模糊匹配 */
    protected static function filterRecords(array $records, $name = null, $ip = null)
    {
        $name = $name === null ? null : self::normalizeName($name);
        return array_values(array_filter($records, function ($record) use ($name, $ip) {
            if ($name !== null && $record['name'] !== $name) {
                return false;
            }
            if ($ip !== null && !in_array($ip, $record['values'], true)) {
                return false;
            }
            return true;
        }));
    }

    protected function ttl()
    {
        return static::defaultTtl();
    }

    /**
     * @return array [int status, string body]
     */
    protected function request($method, $url, array $headers = [], $body = null)
    {
        if ($this->transport) {
            return call_user_func($this->transport, $method, $url, $headers, $body);
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        $lines = [];
        foreach ($headers as $key => $value) {
            $lines[] = $key . ': ' . $value;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $lines);
        if ($body !== null && $body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $responseBody = curl_exec($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($error) {
            throw new Exception(static::label() . ' 网络请求失败：' . $error);
        }
        return [$status, (string) $responseBody];
    }

    protected function requestJson($method, $url, array $headers = [], $payload = null)
    {
        $body = $payload === null ? null : json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($payload !== null && !isset($headers['Content-Type'])) {
            $headers['Content-Type'] = 'application/json';
        }
        [$status, $raw] = $this->request($method, $url, $headers, $body);
        $decoded = $raw === '' ? [] : json_decode($raw, true);
        if ($raw !== '' && !is_array($decoded)) {
            throw new Exception(static::label() . " 返回了无法解析的内容（HTTP {$status}）");
        }
        return [$status, $decoded ?: []];
    }

    protected function fail($status, $detail)
    {
        $detail = trim((string) $detail);
        // 各家表示"密钥不对"的错误码不同，状态码也不统一（400/401/403/404 都有），按错误内容识别
        $credentialError = '/InvalidAccessKeyId|SignatureDoesNotMatch|InvalidClientTokenId|AuthFailure|APIGW\.030|INVALID_API_KEY|Invalid API Key|Invalid request headers|UNABLE_TO_AUTHENTICATE|Unable to authenticate/i';
        if (preg_match($credentialError, $detail) || $status === 401) {
            $hint = '凭据不正确或已失效。';
        } elseif ($status === 403) {
            $hint = '凭据没有操作解析的权限。';
        } else {
            $hint = '';
        }
        throw new Exception(trim($hint . ' ' . static::label() . ' 返回' . ($status ? " HTTP {$status}" : '') . '：' . ($detail ?: '没有返回详情')));
    }
}
