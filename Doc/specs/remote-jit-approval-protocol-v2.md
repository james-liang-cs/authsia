# Remote JIT Approval Protocol V2

V2 extends [Remote JIT Approval Protocol V1](remote-jit-approval-protocol-v1.md)
so iPhone approval can show exact requested-item names without requiring local
vault metadata.

## Compatibility

- `schemaVersion` and `protocolVersion` are exactly `2`.
- V1 and V2 descriptors are not interchangeable; unsupported versions fail
  closed.
- Existing V1 domain-separation strings remain unchanged. The signed descriptor
  version and canonical bytes distinguish V2.
- The CloudKit record and encrypted transport schemas remain V1 because their
  opaque encrypted payload format is unchanged.

## Requested-item change

Each requested item is encoded in this order:

1. item-kind tag;
2. item UUID;
3. required item name;
4. optional normalized folder.

The item name is NFC UTF-8, nonempty, at most 1,024 bytes, and contains no `Cc`
or `Cf` Unicode scalar. It is included in the descriptor digest and Mac
signature. The iPhone displays this signed name directly and never needs to
recover it from its local vault metadata.

All other canonical encoding, validation, signing, encryption, replay
protection, expiry, and decision rules remain as specified by V1.
