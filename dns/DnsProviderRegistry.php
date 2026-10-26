<?php

require_once __DIR__ . '/DnsProvider.php';
require_once __DIR__ . '/CloudflareDnsProvider.php';
require_once __DIR__ . '/HuaweiDnsProvider.php';
require_once __DIR__ . '/AliyunDnsProvider.php';
require_once __DIR__ . '/DnspodDnsProvider.php';
require_once __DIR__ . '/Route53DnsProvider.php';
require_once __DIR__ . '/NamesiloDnsProvider.php';
require_once __DIR__ . '/PorkbunDnsProvider.php';
require_once __DIR__ . '/GodaddyDnsProvider.php';
require_once __DIR__ . '/DigitalOceanDnsProvider.php';

/**
 * 服务商清单，以及配置在 settings 表中的存取规则（ddns_{前缀}_{字段}，密钥字段加密保存）。
 * 新增服务商：写一个 DnsProvider 子类并加到 classes() 里即可，界面会自动出现。
 */
class DnsProviderRegistry
{
    public static function classes()
    {
        return [
            'aliyun' => AliyunDnsProvider::class,
            'dnspod' => DnspodDnsProvider::class,
            'huawei' => HuaweiDnsProvider::class,
            'cloudflare' => CloudflareDnsProvider::class,
            'route53' => Route53DnsProvider::class,
            'namesilo' => NamesiloDnsProvider::class,
            'porkbun' => PorkbunDnsProvider::class,
            'godaddy' => GodaddyDnsProvider::class,
            'digitalocean' => DigitalOceanDnsProvider::class
        ];
    }

    public static function exists($id)
    {
        return isset(self::classes()[$id]);
    }

    public static function normalizeId($id)
    {
        return self::exists($id) ? $id : 'cloudflare';
    }

    /**
     * @param array $settings 已解密的全部设置
     * @return DnsProvider
     */
    public static function create($id, array $settings, callable $transport = null)
    {
        $class = self::classes()[self::normalizeId($id)];
        return new $class(self::configFromSettings($id, $settings), $transport);
    }

    public static function settingKey($id, $field)
    {
        $class = self::classes()[$id];
        return 'ddns_' . $class::settingPrefix() . '_' . $field;
    }

    public static function configFromSettings($id, array $settings)
    {
        $id = self::normalizeId($id);
        $class = self::classes()[$id];
        $config = [];
        foreach ($class::fields() as $field) {
            $value = $settings[self::settingKey($id, $field['key'])] ?? ($field['default'] ?? '');
            $config[$field['key']] = $field['type'] === 'switch' ? ($value === '1' || $value === true) : (string) $value;
        }
        return $config;
    }

    /** 所有加密保存的设置项 */
    public static function secretSettingKeys()
    {
        $keys = [];
        foreach (self::classes() as $id => $class) {
            foreach ($class::fields() as $field) {
                if ($field['type'] === 'secret') {
                    $keys[] = self::settingKey($id, $field['key']);
                }
            }
        }
        return $keys;
    }

    /** 给前端的服务商清单与表单定义 */
    public static function schema()
    {
        $schema = [];
        foreach (self::classes() as $id => $class) {
            $schema[] = [
                'id' => $id,
                'label' => $class::label(),
                'market' => $class::market(),
                'fields' => $class::fields(),
                'hint' => $class::permissionHint(),
                'ttl' => $class::defaultTtl()
            ];
        }
        return $schema;
    }

    /** 前端展示用：密钥只回传掩码 */
    public static function maskedCredentials(array $settings)
    {
        $result = [];
        foreach (self::classes() as $id => $class) {
            $config = self::configFromSettings($id, $settings);
            foreach ($class::fields() as $field) {
                if ($field['type'] === 'secret') {
                    $config[$field['key']] = $config[$field['key']] !== '' ? '********' : '';
                }
            }
            $result[$id] = $config;
        }
        return $result;
    }
}
