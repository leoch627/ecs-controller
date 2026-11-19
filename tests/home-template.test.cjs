const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const root = path.join(__dirname, '..');

test('the shipped Vue compiler can compile the homepage template', () => {
    const html = fs.readFileSync(path.join(root, 'template.html'), 'utf8');
    const start = html.indexOf('<div id="app"');
    const end = html.indexOf('<script src="static/vue.global.prod.js');
    assert.ok(start >= 0 && end > start, 'expected app markup before the Vue script');

    // Vue's runtime compiler uses a temporary DOM node for entity decoding.
    // The app markup is otherwise compiled without mounting it in this test.
    const decode = value => value.replace(/&(quot|apos|lt|gt|amp);/g, (_, name) => ({
        quot: '"', apos: "'", lt: '<', gt: '>', amp: '&'
    })[name]);
    const document = {
        createElement: () => ({
            set innerHTML(value) {
                this.textContent = decode(value);
                const attr = value.match(/^<div foo="(.*)">$/s);
                this.children = attr ? [{ getAttribute: () => decode(attr[1]) }] : [];
            }
        })
    };
    const scope = { document };
    vm.runInNewContext(fs.readFileSync(path.join(root, 'static/vue.global.prod.js'), 'utf8'), scope);
    assert.equal(typeof scope.Vue.compile(html.slice(start, end)), 'function');
});
