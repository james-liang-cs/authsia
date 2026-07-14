(function initHostMatching(root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
    return;
  }
  root.AuthsiaHostMatching = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function createHostMatching() {
  function parseHostFromUrl(input) {
    if (typeof input !== 'string') {
      return null;
    }

    const trimmed = input.trim();
    if (!trimmed) {
      return null;
    }

    const withScheme = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(trimmed)
      ? trimmed
      : `https://${trimmed}`;

    try {
      const url = new URL(withScheme);
      const host = url.hostname.toLowerCase();
      return host || null;
    } catch {
      return null;
    }
  }

  function hostMatches(host, storedHost) {
    if (typeof host !== 'string' || typeof storedHost !== 'string') {
      return false;
    }

    const hostLower = host.trim().toLowerCase();
    const storedLower = storedHost.trim().toLowerCase();

    if (!hostLower || !storedLower) {
      return false;
    }

    const canonicalHost = canonicalizeHost(hostLower);
    const canonicalStored = canonicalizeHost(storedLower);

    if (canonicalHost === canonicalStored) {
      return true;
    }

    if (isObviousPublicSuffix(canonicalStored)) {
      return false;
    }

    return canonicalHost.endsWith(`.${canonicalStored}`);
  }

  function canonicalizeHost(host) {
    return host.startsWith('www.') ? host.slice(4) : host;
  }

  function isObviousPublicSuffix(host) {
    if (!host.includes('.')) {
      return true;
    }

    return new Set([
      'co.uk',
      'com.au',
      'com.br',
      'com.cn',
      'com.sg',
      'com.tr',
      'co.jp',
      'co.nz',
    ]).has(host);
  }

  function selectBestMatch(candidates) {
    if (!Array.isArray(candidates) || candidates.length === 0) {
      return null;
    }

    const exactMatches = candidates.filter((candidate) => candidate && candidate.isExact);

    if (exactMatches.length === 1) {
      return exactMatches[0];
    }

    if (exactMatches.length > 1) {
      return null;
    }

    return candidates.length === 1 ? candidates[0] : null;
  }

  return {
    parseHostFromUrl,
    hostMatches,
    selectBestMatch,
  };
});
