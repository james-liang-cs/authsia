# Remote JIT Approval Protocol V1

## Scope

This document defines the presentation-neutral bytes exchanged by a paired Mac
and iPhone for a single remote JIT approval. A Mac signs a complete approval
descriptor. The iPhone verifies and displays only values derived from that
descriptor, then signs an approve or deny decision bound to the same request.

V1 does not define pairing, key derivation, authenticated encryption, CloudKit
transport, UI, grant creation, or a `BridgeApprover` migration. It grants no
authority by itself. A host may act only after applying its existing local JIT
policy and verifying every binding in this document.

## Canonical primitives

All integers are unsigned unless stated otherwise.

| Value | Encoding |
| --- | --- |
| Tag | `UInt8` |
| Version | `UInt16`, big endian |
| Count or variable length | `UInt32`, big endian |
| Time | nonnegative `Int64` Unix milliseconds, big endian, at most `253402300799999` |
| UUID | 16 RFC-4122/network-order bytes, never text |
| Fixed data | raw bytes without a length |
| String | `UInt32` UTF-8 length followed by bytes |
| Optional | `0x00` when absent or `0x01` followed by the value |
| Collection | `UInt32` count followed by canonical elements |

Date-to-millisecond conversion truncates toward zero. Required strings and
present optional strings are nonempty, NFC/precomposed, contain no NUL or other
unsafe Unicode control scalar, and respect the field-specific UTF-8 byte limit.
For V1, an unsafe control scalar is any scalar whose Unicode General_Category is
`Cc` or `Cf`. A decoder requires received bytes to already have this form; it
never repairs or normalizes input.

A canonical descriptor is at most 1,000,000 bytes. A request or decision
envelope is at most 1,048,576 bytes. Counts and lengths must be checked against
their semantic and enclosing limits before allocating or slicing input.

These exact ASCII domains include their terminal NUL byte:

```text
Authsia.RemoteJITApproval.Descriptor.V1\0
Authsia.RemoteJITApproval.RequestSignature.V1\0
Authsia.RemoteJITApproval.RequestEnvelope.V1\0
Authsia.RemoteJITApproval.DecisionSignature.V1\0
Authsia.RemoteJITApproval.DecisionEnvelope.V1\0
```

## Approval descriptor

`canonicalDescriptorBytes = DescriptorDomain || orderedDescriptorFields`.

| # | Field | Rule |
| ---: | --- | --- |
| 1 | `schemaVersion` | exactly 1 |
| 2 | `protocolVersion` | exactly 1 |
| 3 | `approvalID` | UUID |
| 4 | `approvalNonce` | exactly 32 bytes |
| 5 | `bridgeRequestID` | UUID copied from the bridge request |
| 6 | `pairingGenerationID` | UUID |
| 7 | `macDeviceID` | UUID |
| 8 | `iphoneDeviceID` | UUID |
| 9 | `macSigningKeyFingerprint` | SHA-256 of the trusted 65-byte Mac X9.63 key |
| 10 | `iphoneSigningKeyFingerprint` | SHA-256 of the trusted 65-byte iPhone X9.63 key |
| 11 | `requestIssuedAtMilliseconds` | canonical time |
| 12 | `requestExpiresAtMilliseconds` | issued time plus exactly 90,000 |
| 13 | `callerFingerprint` | nested fields below |
| 14 | `capabilities` | canonical collection below |
| 15 | `folderScope` | tagged union below |
| 16 | `environmentScope` | tagged union below |
| 17 | `requestedItems` | canonical collection below |
| 18 | `grantIssuedAtMilliseconds` | exactly the request-issued time |
| 19 | `grantExpiresAtMilliseconds` | grant lifetime is `1...86_400_000` milliseconds |

The caller fingerprint has this order: required process name; optional bundle
identifier, signing team identifier, signing identity, parent process name,
parent bundle identifier, host process name, and host bundle identifier; then
required session scope and normalized absolute working directory. Remote
approval is unavailable if the latter two values are absent. String byte limits
are 255 for process, bundle, team, and environment names; 1,024 for signing
identity and session scope; and 4,096 for working directory and folder path.

Working-directory normalization is lexical and filesystem-independent. It
requires an absolute POSIX path, removes empty and `.` components, resolves `..`
by removing one prior component, rejects traversal above root, preserves NFC
component spelling and case, and rejoins beneath `/`. It does not expand `~` or
resolve symlinks.

### Authority fields

Capability tags are `exec = 0x01` and `list = 0x02`. The only legal sequences
are `[list]` and `[exec, list]`.

Folder tags are `root = 0x00` and `folderAndDescendants = 0x01` followed by a
string. A folder path uses the existing `normalizeFolderPath` behavior: split on
`/`, trim the frozen Foundation whitespace-and-newline mirror from each segment,
discard empty segments, and rejoin with `/`. That trim set is exactly
U+0009...U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000...U+200B, U+2028,
U+2029, U+202F, U+205F, and U+3000. A received named folder must already equal
that normalized nonempty result and therefore cannot carry a trimmed `Cf`
scalar on the wire.

Environment tags are `unrestricted(nil) = 0x00`, `defaultOnly = 0x01`, and
`named = 0x02` followed by a string. A named environment trims only ASCII
U+0009...U+000D and U+0020 from both ends, converts to NFC, rejects an empty
result and all remaining Unicode control scalars, and preserves spelling and
case. Here and throughout V1, “control scalars” means Unicode General_Category
`Cc` or `Cf`. A decoder requires exact equality with this normalized result. A
later host may authorize environment names case-insensitively, but wire bytes
never case-fold.

Item tags are `password = 0x01`, `apiKey = 0x02`, `certificate = 0x03`,
`note = 0x04`, and `ssh = 0x05`. Each item contains its tag, UUID, and optional
normalized folder. Items are bytewise sorted by tag, UUID bytes, folder marker,
and folder UTF-8 bytes. Duplicate UUIDs, zero items, more than 1,024 items,
items outside the descriptor folder scope, and SSH items under exec authority
are invalid.

Display strings are derived rather than carried as redundant free-form fields.
The agent label comes from the caller fingerprint. The workspace label is `/`
for the root working directory and otherwise its last normalized component.
Scope, environment, duration, and requested item counts and kinds come from the
signed authority fields. The Mac label comes from the trusted pairing record.
UI renders derived strings with normal platform escaping; a pairing layer must
apply the same no-`Cc`/`Cf` rule to the Mac label.

## Signed request

```text
requestDigest = SHA256(canonicalDescriptorBytes)
requestSigningPreimage = RequestSignatureDomain || requestDigest
requestEnvelope = RequestEnvelopeDomain
               || UInt32(descriptorLength)
               || canonicalDescriptorBytes
               || requestDigest[32]
               || requestSignature[64]
```

`descriptorLength` includes the descriptor domain and all ordered fields.

Before showing a request, the iPhone verifies the signature with the currently
trusted Mac key and requires the expected pairing generation, Mac device,
iPhone device, Mac key fingerprint, and iPhone key fingerprint. It also rejects
the request as expired when
`evaluatedAtMilliseconds >= requestExpiresAtMilliseconds`.

## Signed decision

The unsigned decision body contains, in order: schema version, protocol
version, approval UUID, 32-byte nonce, 32-byte request digest, pairing generation
UUID, Mac device UUID, iPhone device UUID, decision tag (`approve = 0x01` or
`deny = 0x02`), and the request expiry copied exactly from the descriptor.

```text
decisionSigningPreimage = DecisionSignatureDomain || unsignedDecisionBody
decisionEnvelope = DecisionEnvelopeDomain
                || unsignedDecisionBody
                || decisionSignature[64]
```

There is no decision-created timestamp. The Mac accepts only a decision whose
copied fields equal its verified request and current pairing binding. The host
owns the monotonic deadline and first-result-wins state.

## P-256 representation and signature rules

Public keys are exactly 65-byte uncompressed X9.63 points beginning with
`0x04`. Signatures use ECDSA P-256 with SHA-256 over the stated signing
preimage and are exactly 64-byte IEEE P1363 `r || s` values. Both scalars must
be nonzero and below the P-256 order, and verification additionally requires
low S: `s <= floor(n / 2)`.

```text
n      = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
n / 2  = 7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8
```

A signer replaces high S with `n - s`. A verifier rejects high-S input instead
of normalizing it.

## Strict decoding

A decoder rejects unknown versions or tags, invalid optional markers,
truncation, trailing bytes, invalid UTF-8, non-NFC or unsafe strings,
noncanonical paths or named environments, oversized lengths, invalid counts,
duplicates, unsorted collections, impossible time relationships, and
inconsistent bindings. It never ignores unknown fields, reorders collections,
or repairs received bytes. Signature scalar and low-S validation is part of
cryptographic verification.
