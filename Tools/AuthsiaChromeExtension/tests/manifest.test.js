const assert = require('assert');
const path = require('path');

const manifest = require(path.join(__dirname, '..', 'manifest.json'));

assert.ok(
  !Object.prototype.hasOwnProperty.call(manifest, 'host_permissions'),
  'static content scripts must not also grant redundant extension-wide host permissions'
);

assert.strictEqual(manifest.web_accessible_resources.length, 1);
assert.deepStrictEqual(
  manifest.web_accessible_resources[0].resources,
  ['popup/menu.html'],
  'websites should only be able to navigate to the injected menu entry page'
);
assert.strictEqual(
  manifest.web_accessible_resources[0].use_dynamic_url,
  true,
  'web-accessible resources should use a per-session dynamic URL'
);

console.log('manifest tests passed');
