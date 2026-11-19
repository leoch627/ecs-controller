const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const template = fs.readFileSync(path.join(__dirname, '..', 'template.html'), 'utf8');
const script = template.slice(template.indexOf('                const canCheckIp ='), template.indexOf('                const controlInstance ='));
const flush = () => new Promise(resolve => setImmediate(resolve));

test('opening instance management uses a new probe and ignores cached or aborted results', async () => {
    const inst = { id: 1, publicIp: '1.1.1.1', instanceStatus: 'Running', ipCheck: { status: 'ok' } };
    const requests = [];
    const ctx = vm.createContext({
        ref: value => ({ value }), allInstances: { value: [inst] }, currentMenu: { value: 'manage' },
        isAdmin: { value: true }, ipCheckEnabled: { value: true }, document: { hidden: false }, AbortController,
        fetch: (_url, options) => new Promise(resolve => requests.push({ resolve, signal: options.signal }))
    });
    const ui = vm.runInContext(script + '\n({startIpCheckVisit, ipCheckBadge})', ctx);
    const respond = (i, data) => requests[i].resolve({ ok: true, json: async () => ({ success: true, data }) });
    assert.match(ui.ipCheckBadge(inst).text, /等待/);
    ui.startIpCheckVisit();
    assert.match(ui.ipCheckBadge(inst).text, /检测中/);
    respond(0, { ip: inst.publicIp, port: 22, status: 'blocked', checkedAt: 1 });
    await flush();
    assert.match(ui.ipCheckBadge(inst).text, /TCP 22 疑似被墙/);
    ui.startIpCheckVisit();
    ui.startIpCheckVisit();
    assert.equal(requests[1].signal.aborted, true);
    respond(1, { ip: inst.publicIp, port: 22, status: 'ok', checkedAt: 2 });
    await flush();
    assert.match(ui.ipCheckBadge(inst).text, /检测中/);
    respond(2, { ip: inst.publicIp, port: 22, status: 'ok', refused: true, checkedAt: 3 });
    await flush();
    assert.match(ui.ipCheckBadge(inst).text, /TCP 22 端口拒绝连接/);
});
