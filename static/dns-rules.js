(function (root) {
    'use strict';
    const normalizeDomain = value => String(value || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^\.+|\.+$/g, '');
    const fqdn = rule => {
        const domain = normalizeDomain(rule.domain);
        const name = String(rule.name || '').trim().toLowerCase().replace(/\.$/, '');
        if (!domain || !name) return '';
        if (name === '@' || name === domain) return domain;
        return name.endsWith('.' + domain) ? name : `${name}.${domain}`;
    };
    const matches = (rule, instance) => {
        if (!instance.instanceId) return false;
        const scope = rule.scope || {};
        switch (scope.mode) {
            case 'all': return true;
            case 'aliyun': return ['', 'china', 'international'].includes(instance.siteType || '');
            case 'aws': return instance.siteType === 'aws';
            case 'groups': return (scope.group_keys || []).includes(instance.groupKey);
            case 'instances': return !!instance.dnsInstanceKey && (scope.instance_keys || []).includes(instance.dnsInstanceKey);
            default: return false;
        }
    };
    const normalize = rule => ({
        ...rule,
        zone_id: rule.zone_id || '',
        name: rule.name || '',
        scope: { mode: rule.scope?.mode || 'aliyun', group_keys: [...(rule.scope?.group_keys || [])], instance_keys: [...(rule.scope?.instance_keys || [])] }
    });
    const api = { normalizeDomain, fqdn, matches, normalize };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.ECSDNSRules = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
