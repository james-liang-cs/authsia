import assert from "node:assert/strict";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const VERSION = 1;
const REQUEST_LIFETIME_MILLISECONDS = 90_000;
const MAX_TIME_MILLISECONDS = 253_402_300_799_999;
const P256_ORDER = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
const P256_HALF_ORDER = BigInt("0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");

const DOMAINS = Object.freeze({
  descriptor: Buffer.from("Authsia.RemoteJITApproval.Descriptor.V1\0", "ascii"),
  requestSignature: Buffer.from("Authsia.RemoteJITApproval.RequestSignature.V1\0", "ascii"),
  requestEnvelope: Buffer.from("Authsia.RemoteJITApproval.RequestEnvelope.V1\0", "ascii"),
  decisionSignature: Buffer.from("Authsia.RemoteJITApproval.DecisionSignature.V1\0", "ascii"),
  decisionEnvelope: Buffer.from("Authsia.RemoteJITApproval.DecisionEnvelope.V1\0", "ascii"),
});
const FOUNDATION_WHITESPACE_AND_NEWLINES =
  /^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/gu;

const sha256 = data => createHash("sha256").update(data).digest();
const hex = data => data.toString("hex");

function u8(value) {
  assert(Number.isInteger(value) && value >= 0 && value <= 0xff);
  return Buffer.from([value]);
}

function u16(value) {
  assert(Number.isInteger(value) && value >= 0 && value <= 0xffff);
  const data = Buffer.alloc(2);
  data.writeUInt16BE(value);
  return data;
}

function u32(value) {
  assert(Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff);
  const data = Buffer.alloc(4);
  data.writeUInt32BE(value);
  return data;
}

function i64(value) {
  assert(Number.isSafeInteger(value) && value >= 0 && value <= MAX_TIME_MILLISECONDS);
  const data = Buffer.alloc(8);
  data.writeBigInt64BE(BigInt(value));
  return data;
}

function fixedHex(value, length, label) {
  assert.equal(typeof value, "string", `${label} must be hexadecimal text`);
  assert.match(value, /^[0-9a-f]+$/, `${label} must be lowercase hexadecimal text`);
  assert.equal(value.length, length * 2, `${label} must be ${length} bytes`);
  return Buffer.from(value, "hex");
}

function uuid(value) {
  assert.match(
    value,
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    `invalid UUID: ${value}`,
  );
  return Buffer.from(value.replaceAll("-", ""), "hex");
}

function protocolString(value, maximumBytes, label) {
  assert.equal(typeof value, "string", `${label} must be text`);
  assert(value.length > 0, `${label} must not be empty`);
  for (const scalar of value) {
    assert(
      !(scalar.length === 1 && scalar.charCodeAt(0) >= 0xd800 && scalar.charCodeAt(0) <= 0xdfff),
      `${label} contains an unpaired surrogate`,
    );
  }
  assert.equal(value, value.normalize("NFC"), `${label} must already be NFC`);
  assert(!/\p{Cc}/u.test(value), `${label} contains a control scalar`);
  const encoded = Buffer.from(value, "utf8");
  assert(encoded.length > 0 && encoded.length <= maximumBytes, `${label} exceeds its byte limit`);
  return Buffer.concat([u32(encoded.length), encoded]);
}

function optionalString(value, maximumBytes, label) {
  return value === null
    ? u8(0)
    : Buffer.concat([u8(1), protocolString(value, maximumBytes, label)]);
}

function normalizeFolderPath(value) {
  if (value === null) return null;
  const components = value
    .split("/")
    .map(component => component.replace(FOUNDATION_WHITESPACE_AND_NEWLINES, ""))
    .filter(component => component.length > 0);
  return components.length === 0 ? null : components.join("/");
}

function canonicalFolder(value, label) {
  const normalized = normalizeFolderPath(value);
  assert(normalized !== null, `${label} must not be empty`);
  assert.equal(value, normalized, `${label} must already be normalized`);
  return protocolString(value, 4_096, label);
}

function normalizeNamedEnvironment(value) {
  return value
    .replace(/^[\u0009-\u000d\u0020]+|[\u0009-\u000d\u0020]+$/g, "")
    .normalize("NFC");
}

function canonicalNamedEnvironment(value) {
  const normalized = normalizeNamedEnvironment(value);
  assert(normalized.length > 0, "named environment must not be empty");
  assert(!/\p{Cc}/u.test(normalized), "named environment contains a control scalar");
  assert.equal(value, normalized, "named environment must already be normalized");
  return protocolString(value, 255, "named environment");
}

function normalizeWorkingDirectory(value) {
  assert.equal(typeof value, "string");
  assert(value.startsWith("/"), "working directory must be absolute");
  const output = [];
  for (const rawComponent of value.split("/")) {
    if (rawComponent === "" || rawComponent === ".") continue;
    if (rawComponent === "..") {
      assert(output.length > 0, "working directory traverses above root");
      output.pop();
      continue;
    }
    assert.equal(rawComponent, rawComponent.normalize("NFC"), "working-directory component must be NFC");
    assert(!/\p{Cc}/u.test(rawComponent), "working-directory component contains a control scalar");
    output.push(rawComponent);
  }
  return `/${output.join("/")}`;
}

function callerBytes(caller) {
  assert.equal(caller.workingDirectory, normalizeWorkingDirectory(caller.workingDirectory));
  return Buffer.concat([
    protocolString(caller.processName, 255, "process name"),
    optionalString(caller.bundleIdentifier, 255, "bundle identifier"),
    optionalString(caller.signingTeamIdentifier, 255, "signing team identifier"),
    optionalString(caller.signingIdentity, 1_024, "signing identity"),
    optionalString(caller.parentProcessName, 255, "parent process name"),
    optionalString(caller.parentBundleIdentifier, 255, "parent bundle identifier"),
    optionalString(caller.hostProcessName, 255, "host process name"),
    optionalString(caller.hostBundleIdentifier, 255, "host bundle identifier"),
    protocolString(caller.sessionScope, 1_024, "session scope"),
    protocolString(caller.workingDirectory, 4_096, "working directory"),
  ]);
}

const CAPABILITY_TAGS = Object.freeze({ exec: 0x01, list: 0x02 });
const ITEM_TAGS = Object.freeze({
  password: 0x01,
  apiKey: 0x02,
  certificate: 0x03,
  note: 0x04,
  ssh: 0x05,
});

function capabilityBytes(capabilities) {
  assert(
    JSON.stringify(capabilities) === JSON.stringify(["list"])
      || JSON.stringify(capabilities) === JSON.stringify(["exec", "list"]),
    "capabilities must be [list] or [exec, list]",
  );
  return Buffer.concat([u32(capabilities.length), ...capabilities.map(value => u8(CAPABILITY_TAGS[value]))]);
}

function folderScopeBytes(folderScope) {
  if (folderScope === "root") return u8(0);
  return Buffer.concat([u8(1), canonicalFolder(folderScope, "folder scope")]);
}

function environmentScopeBytes(environmentScope) {
  if (environmentScope === null) return u8(0);
  if (environmentScope === "defaultOnly") return u8(1);
  return Buffer.concat([u8(2), canonicalNamedEnvironment(environmentScope)]);
}

function itemBytes(item) {
  const tag = ITEM_TAGS[item.kind];
  assert(tag !== undefined, `unknown item kind: ${item.kind}`);
  const folder = item.folderPath === null
    ? u8(0)
    : Buffer.concat([u8(1), canonicalFolder(item.folderPath, "item folder")]);
  return Buffer.concat([u8(tag), uuid(item.id), folder]);
}

function requestedItemBytes(input) {
  assert(input.items.length > 0 && input.items.length <= 1_024, "item count is outside V1 limits");
  const seen = new Set();
  const encoded = input.items.map(item => {
    assert(!seen.has(item.id), `duplicate item UUID: ${item.id}`);
    seen.add(item.id);
    if (input.capabilities.includes("exec")) {
      assert.notEqual(item.kind, "ssh", "SSH is not legal under exec authority");
    }
    if (input.folderScope === "root") {
      assert.equal(item.folderPath, null, "root scope accepts only root items");
    } else {
      const folder = normalizeFolderPath(item.folderPath);
      assert(
        folder === input.folderScope || folder?.startsWith(`${input.folderScope}/`),
        "item is outside the descriptor folder scope",
      );
    }
    return itemBytes(item);
  });
  for (let index = 1; index < encoded.length; index += 1) {
    assert(Buffer.compare(encoded[index - 1], encoded[index]) < 0, "items must already be canonically sorted");
  }
  return Buffer.concat([u32(encoded.length), ...encoded]);
}

function descriptorBytes(input, requestPublicKey, decisionPublicKey) {
  assert.equal(input.requestExpiresAtMilliseconds - input.requestIssuedAtMilliseconds, REQUEST_LIFETIME_MILLISECONDS);
  assert.equal(input.grantIssuedAtMilliseconds, input.requestIssuedAtMilliseconds);
  const grantLifetime = input.grantExpiresAtMilliseconds - input.grantIssuedAtMilliseconds;
  assert(grantLifetime >= 1 && grantLifetime <= 86_400_000, "grant lifetime is outside V1 limits");

  const descriptor = Buffer.concat([
    DOMAINS.descriptor,
    u16(VERSION),
    u16(VERSION),
    uuid(input.approvalID),
    fixedHex(input.approvalNonceHex, 32, "approval nonce"),
    uuid(input.bridgeRequestID),
    uuid(input.pairingGenerationID),
    uuid(input.macDeviceID),
    uuid(input.iphoneDeviceID),
    sha256(requestPublicKey),
    sha256(decisionPublicKey),
    i64(input.requestIssuedAtMilliseconds),
    i64(input.requestExpiresAtMilliseconds),
    callerBytes(input.caller),
    capabilityBytes(input.capabilities),
    folderScopeBytes(input.folderScope),
    environmentScopeBytes(input.environmentScope),
    requestedItemBytes(input),
    i64(input.grantIssuedAtMilliseconds),
    i64(input.grantExpiresAtMilliseconds),
  ]);
  assert(descriptor.length <= 1_000_000, "descriptor exceeds V1 limit");
  return descriptor;
}

function unsignedDecisionBytes(input, requestDigest, decisionTag) {
  assert(decisionTag === 0x01 || decisionTag === 0x02);
  return Buffer.concat([
    u16(VERSION),
    u16(VERSION),
    uuid(input.approvalID),
    fixedHex(input.approvalNonceHex, 32, "approval nonce"),
    requestDigest,
    uuid(input.pairingGenerationID),
    uuid(input.macDeviceID),
    uuid(input.iphoneDeviceID),
    u8(decisionTag),
    i64(input.requestExpiresAtMilliseconds),
  ]);
}

function bigIntFromBytes(data) {
  return BigInt(`0x${hex(data)}`);
}

function bigIntBytes(value, length) {
  const encoded = value.toString(16).padStart(length * 2, "0");
  assert(encoded.length <= length * 2);
  return Buffer.from(encoded, "hex");
}

function validateLowSSignature(signature) {
  assert.equal(signature.length, 64, "signature must be 64 bytes");
  const r = bigIntFromBytes(signature.subarray(0, 32));
  const s = bigIntFromBytes(signature.subarray(32));
  assert(r >= 1n && r < P256_ORDER, "signature r is outside the P-256 range");
  assert(s >= 1n && s <= P256_HALF_ORDER, "signature s is not canonical low-S");
}

function normalizeLowS(signature) {
  assert.equal(signature.length, 64);
  const r = signature.subarray(0, 32);
  const rValue = bigIntFromBytes(r);
  let s = bigIntFromBytes(signature.subarray(32));
  assert(rValue >= 1n && rValue < P256_ORDER);
  assert(s >= 1n && s < P256_ORDER);
  if (s > P256_HALF_ORDER) s = P256_ORDER - s;
  const normalized = Buffer.concat([r, bigIntBytes(s, 32)]);
  validateLowSSignature(normalized);
  return normalized;
}

function publicKeyX963(publicKey) {
  const jwk = publicKey.export({ format: "jwk" });
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  assert.equal(x.length, 32);
  assert.equal(y.length, 32);
  return Buffer.concat([u8(0x04), x, y]);
}

function publicKeyFromX963(data) {
  assert.equal(data.length, 65, "P-256 public key must be 65 bytes");
  assert.equal(data[0], 0x04, "P-256 public key must be uncompressed X9.63");
  return createPublicKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: data.subarray(1, 33).toString("base64url"),
      y: data.subarray(33, 65).toString("base64url"),
    },
    format: "jwk",
  });
}

function signLowS(preimage, privateKey) {
  const signature = sign("sha256", preimage, {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return normalizeLowS(signature);
}

function verifySignature(preimage, signature, publicKey) {
  validateLowSSignature(signature);
  assert(
    verify("sha256", preimage, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature),
    "signature verification failed",
  );
}

function syntheticInput() {
  return {
    approvalID: "11111111-1111-4111-8111-111111111111",
    approvalNonceHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    bridgeRequestID: "22222222-2222-4222-8222-222222222222",
    pairingGenerationID: "33333333-3333-4333-8333-333333333333",
    macDeviceID: "44444444-4444-4444-8444-444444444444",
    iphoneDeviceID: "55555555-5555-4555-8555-555555555555",
    requestIssuedAtMilliseconds: 2_000_000_000_000,
    requestExpiresAtMilliseconds: 2_000_000_090_000,
    caller: {
      processName: "synthetic-agent",
      bundleIdentifier: "example.synthetic.agent",
      signingTeamIdentifier: "SYNTHETIC",
      signingIdentity: "Synthetic Development Identity",
      parentProcessName: "synthetic-parent",
      parentBundleIdentifier: null,
      hostProcessName: "synthetic-host",
      hostBundleIdentifier: "example.synthetic.host",
      sessionScope: "synthetic-session",
      workingDirectory: "/workspace/synthetic-demo",
    },
    capabilities: ["exec", "list"],
    folderScope: "Team/API",
    environmentScope: "Production",
    items: [
      {
        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        kind: "password",
        folderPath: "Team/API",
      },
      {
        id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        kind: "apiKey",
        folderPath: "Team/API/Build",
      },
    ],
    grantIssuedAtMilliseconds: 2_000_000_000_000,
    grantExpiresAtMilliseconds: 2_000_000_300_000,
  };
}

function makeFixture() {
  const input = syntheticInput();
  const requestPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const decisionPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const requestPublicKey = publicKeyX963(requestPair.publicKey);
  const decisionPublicKey = publicKeyX963(decisionPair.publicKey);
  assert.notDeepEqual(requestPublicKey, decisionPublicKey, "request and decision keys must be distinct");

  const descriptor = descriptorBytes(input, requestPublicKey, decisionPublicKey);
  const requestDigest = sha256(descriptor);
  const requestPreimage = Buffer.concat([DOMAINS.requestSignature, requestDigest]);
  const requestSignature = signLowS(requestPreimage, requestPair.privateKey);
  const requestEnvelope = Buffer.concat([
    DOMAINS.requestEnvelope,
    u32(descriptor.length),
    descriptor,
    requestDigest,
    requestSignature,
  ]);

  const unsignedApproveDecision = unsignedDecisionBytes(input, requestDigest, 0x01);
  const unsignedDenyDecision = unsignedDecisionBytes(input, requestDigest, 0x02);
  const approveDecisionSignature = signLowS(
    Buffer.concat([DOMAINS.decisionSignature, unsignedApproveDecision]),
    decisionPair.privateKey,
  );
  const denyDecisionSignature = signLowS(
    Buffer.concat([DOMAINS.decisionSignature, unsignedDenyDecision]),
    decisionPair.privateKey,
  );
  const approveDecisionEnvelope = Buffer.concat([
    DOMAINS.decisionEnvelope,
    unsignedApproveDecision,
    approveDecisionSignature,
  ]);
  const denyDecisionEnvelope = Buffer.concat([
    DOMAINS.decisionEnvelope,
    unsignedDenyDecision,
    denyDecisionSignature,
  ]);

  assert(requestEnvelope.length <= 1_048_576);
  assert(approveDecisionEnvelope.length <= 1_048_576);
  assert(denyDecisionEnvelope.length <= 1_048_576);

  return {
    input,
    expected: {
      descriptorHex: hex(descriptor),
      requestDigestHex: hex(requestDigest),
      requestEnvelopeHex: hex(requestEnvelope),
      requestPublicKeyX963Hex: hex(requestPublicKey),
      requestSignatureHex: hex(requestSignature),
      unsignedApproveDecisionHex: hex(unsignedApproveDecision),
      unsignedDenyDecisionHex: hex(unsignedDenyDecision),
      approveDecisionEnvelopeHex: hex(approveDecisionEnvelope),
      approveDecisionSignatureHex: hex(approveDecisionSignature),
      denyDecisionEnvelopeHex: hex(denyDecisionEnvelope),
      denyDecisionSignatureHex: hex(denyDecisionSignature),
      decisionPublicKeyX963Hex: hex(decisionPublicKey),
    },
  };
}

function assertPublicOnly(value) {
  if (Array.isArray(value)) {
    for (const element of value) assertPublicOnly(element);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      assert.notEqual(key, "d", "fixture must not contain a JWK private scalar");
      assert(!key.toLowerCase().includes("private"), "fixture must not contain private-key fields");
      assertPublicOnly(nested);
    }
  }
}

function expectedHex(actual, expected, label) {
  assert.equal(hex(actual), expected, `${label} does not match the independent recomputation`);
}

function verifyFixture(fixture) {
  assert.deepEqual(Object.keys(fixture).sort(), ["expected", "input"]);
  assertPublicOnly(fixture);
  const { input, expected } = fixture;
  const requestPublicKey = fixedHex(expected.requestPublicKeyX963Hex, 65, "request public key");
  const decisionPublicKey = fixedHex(expected.decisionPublicKeyX963Hex, 65, "decision public key");
  assert.notDeepEqual(requestPublicKey, decisionPublicKey, "request and decision keys must be distinct");

  const descriptor = descriptorBytes(input, requestPublicKey, decisionPublicKey);
  const requestDigest = sha256(descriptor);
  const requestSignature = fixedHex(expected.requestSignatureHex, 64, "request signature");
  const requestPreimage = Buffer.concat([DOMAINS.requestSignature, requestDigest]);
  verifySignature(requestPreimage, requestSignature, publicKeyFromX963(requestPublicKey));
  const requestEnvelope = Buffer.concat([
    DOMAINS.requestEnvelope,
    u32(descriptor.length),
    descriptor,
    requestDigest,
    requestSignature,
  ]);

  const unsignedApproveDecision = unsignedDecisionBytes(input, requestDigest, 0x01);
  const unsignedDenyDecision = unsignedDecisionBytes(input, requestDigest, 0x02);
  const approveDecisionSignature = fixedHex(
    expected.approveDecisionSignatureHex,
    64,
    "approve decision signature",
  );
  const denyDecisionSignature = fixedHex(
    expected.denyDecisionSignatureHex,
    64,
    "deny decision signature",
  );
  const decisionKey = publicKeyFromX963(decisionPublicKey);
  verifySignature(
    Buffer.concat([DOMAINS.decisionSignature, unsignedApproveDecision]),
    approveDecisionSignature,
    decisionKey,
  );
  verifySignature(
    Buffer.concat([DOMAINS.decisionSignature, unsignedDenyDecision]),
    denyDecisionSignature,
    decisionKey,
  );
  const approveDecisionEnvelope = Buffer.concat([
    DOMAINS.decisionEnvelope,
    unsignedApproveDecision,
    approveDecisionSignature,
  ]);
  const denyDecisionEnvelope = Buffer.concat([
    DOMAINS.decisionEnvelope,
    unsignedDenyDecision,
    denyDecisionSignature,
  ]);

  expectedHex(descriptor, expected.descriptorHex, "descriptor");
  expectedHex(requestDigest, expected.requestDigestHex, "request digest");
  expectedHex(requestEnvelope, expected.requestEnvelopeHex, "request envelope");
  expectedHex(unsignedApproveDecision, expected.unsignedApproveDecisionHex, "unsigned approve decision");
  expectedHex(unsignedDenyDecision, expected.unsignedDenyDecisionHex, "unsigned deny decision");
  expectedHex(approveDecisionEnvelope, expected.approveDecisionEnvelopeHex, "approve decision envelope");
  expectedHex(denyDecisionEnvelope, expected.denyDecisionEnvelopeHex, "deny decision envelope");
}

const [mode, path, ...extra] = process.argv.slice(2);
assert(extra.length === 0 && path, "usage: generate-remote-jit-approval-v1-vectors.mjs (--generate|--verify) path");

if (mode === "--generate") {
  const fixture = makeFixture();
  verifyFixture(fixture);
  writeFileSync(path, `${JSON.stringify(fixture, null, 2)}\n`, { encoding: "utf8", flag: "w" });
} else if (mode === "--verify") {
  verifyFixture(JSON.parse(readFileSync(path, "utf8")));
} else {
  assert.fail("mode must be --generate or --verify");
}
