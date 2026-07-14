const assert = require('assert');
const { parseHostFromUrl, hostMatches, selectBestMatch } = require('../host_matching');

function testParseHostFromUrl() {
  assert.strictEqual(parseHostFromUrl('https://example.com/login'), 'example.com');
  assert.strictEqual(parseHostFromUrl('http://sub.example.com'), 'sub.example.com');
  assert.strictEqual(parseHostFromUrl('example.com/path'), 'example.com');
  assert.strictEqual(parseHostFromUrl('not a url'), null);
}

function testHostMatches() {
  assert.strictEqual(hostMatches('example.com', 'example.com'), true);
  assert.strictEqual(hostMatches('sub.example.com', 'example.com'), true);
  assert.strictEqual(hostMatches('badexample.com', 'example.com'), false);
  assert.strictEqual(hostMatches('example.com', 'sub.example.com'), false);
  assert.strictEqual(hostMatches('example.com', 'www.example.com'), true);
  assert.strictEqual(hostMatches('www.example.com', 'example.com'), true);
  assert.strictEqual(hostMatches('example.com', 'com'), false);
  assert.strictEqual(hostMatches('example.co.uk', 'co.uk'), false);
}

function testSelectBestMatchPrefersExact() {
  const candidates = [
    { id: '1', storedHost: 'example.com', isExact: false },
    { id: '2', storedHost: 'sub.example.com', isExact: true },
  ];

  const match = selectBestMatch(candidates);
  assert.strictEqual(match.id, '2');
}

function run() {
  testParseHostFromUrl();
  testHostMatches();
  testSelectBestMatchPrefersExact();
  console.log('hostMatching tests passed');
}

run();
