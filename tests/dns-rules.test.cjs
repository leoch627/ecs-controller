'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const rules = require('../static/dns-rules.js');

test('preview scopes keep Alibaba Cloud and AWS separate and explicit selections stable', () => {
    const ali = { instanceId: 'i-ali', id: 1, siteType: 'international', groupKey: 'ali', dnsInstanceKey: 'stable-ali' };
    const aws = { instanceId: 'lightsail', siteType: 'aws', groupKey: 'aws', dnsInstanceKey: 'stable-aws' };
    const members = scope => [ali, aws].filter(i => rules.matches({ scope }, i));
    assert.deepEqual(members({ mode: 'aliyun' }), [ali]);
    assert.deepEqual(members({ mode: 'aws' }), [aws]);
    assert.deepEqual(members({ mode: 'groups', group_keys: ['ali'] }), [ali]);
    assert.deepEqual(members({ mode: 'instances', instance_keys: ['stable-aws'] }), [aws]);
    assert.deepEqual(members({ mode: 'instances', instance_keys: [] }), []);
    assert.deepEqual(members({ mode: 'invalid' }), []);
    ali.id = 99;
    assert.deepEqual(members({ mode: 'instances', instance_keys: ['stable-ali'] }), [ali]);
});

test('domain preview handles roots, full names and empty drafts', () => {
    for (const [name, expected] of [['loadbalance', 'loadbalance.example.com'], ['@', 'example.com'], ['rr.EXAMPLE.com.', 'rr.example.com'], ['', '']]) {
        assert.equal(rules.fqdn({ domain: 'https://Example.COM/', name }), expected);
    }
    assert.equal(rules.fqdn({ domain: '', name: 'rr' }), '');
});

test('normalization makes legacy null selections editable without sharing arrays', () => {
    const source = { scope: { mode: 'groups', group_keys: ['ali'], instance_keys: null } };
    const draft = rules.normalize(source);
    draft.scope.group_keys.push('aws');
    assert.deepEqual(source.scope.group_keys, ['ali']);
    assert.deepEqual(draft.scope.instance_keys, []);
});
