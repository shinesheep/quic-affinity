# Routable CID Profile

This document defines the first QUIC-stack-neutral server CID profile for
`quic-affinity`.

The profile is optional. Existing CID map registration remains valid and takes
priority. When profile v1 is enabled for a listener, the BPF dataplane can
validate a profile CID and select the embedded worker ID after a CID map miss.

## Goals

- Keep the CID short enough for common deployments.
- Encode a stable worker ID.
- Include random per-CID entropy.
- Detect accidental or unauthenticated mutation before routing.
- Keep the API independent of a specific QUIC stack.

## v1 Layout

`QAFF_CID_PROFILE_V1_LEN` is 8 bytes:

```text
byte 0      high nibble: version = 1
            low nibble: profile flags, currently 0
bytes 1..2  worker_id, big endian, 16-bit
bytes 3..5  nonce, big endian, 24-bit
bytes 6..7  keyed tag, big endian, 16-bit
```

The v1 worker ID range is `0..65535`. The nonce range is `0..16777215`.
Servers should choose a fresh nonce for every issued CID for a listener key.

## Keying

The helper API takes a 16-byte profile key:

```c
struct qaff_cid_profile_key key;
```

The current tag is a small keyed integrity tag intended to catch malformed,
stale, or wrongly-keyed CIDs before registration. It is not a confidentiality
scheme and should not be treated as a strong cryptographic MAC. A later profile
version can replace the tag algorithm while keeping v1 parsing stable.

Deployments that do not want to expose worker IDs should use a future encrypted
or wider-authenticated profile, or keep using opaque CIDs plus explicit CID map
registration.

## API

Generate:

```c
uint8_t cid[QAFF_CID_PROFILE_V1_LEN];
qaff_cid_profile_v1_generate(&key, worker_id, nonce, cid, sizeof(cid));
```

Parse:

```c
struct qaff_cid_profile_v1_fields fields;
qaff_cid_profile_v1_parse(&key, cid, cid_len, &fields);
```

There are two valid integration choices.

In low-state mode, enable the listener profile key and issue profile CIDs
without per-CID registration:

```c
struct qaff_options options;
qaff_options_init(&options);
options.short_cid_len = QAFF_CID_PROFILE_V1_LEN;
options.cid_profile_v1_enabled = 1;
memcpy(options.cid_profile_v1_key, key.bytes, sizeof(options.cid_profile_v1_key));
```

With `qaffd`, store the same 16-byte listener key as 32 hex digits in a file
readable by the daemon. For regular files, `qaffd` rejects key files that grant
group or other permissions:

```sh
qaffd --socket /tmp/qaffd.sock \
      --bpf /usr/libexec/quic-affinity/qaff_reuseport.bpf.o \
      --short-cid-len 8 \
      --cid-profile-v1-key-file /etc/quic-affinity/profile-v1.key
```

`--cid-profile-v1-key HEX32` also exists for tests and local development, but
production deployments should prefer the file form so the key is not exposed in
process arguments.

In compatibility mode, the server may still register generated CIDs through the
normal control API. Explicit CID-map entries have priority over profile routing:

```c
qaff_control_register_cid(control_fd, fields.worker_id, cid, cid_len);
```

## Operational Notes

- Use a separate key per listener or deployment domain.
- The current BPF config accepts one v1 key at a time. Key rotation needs a
  drain window using CID registration, a second listener instance, or a future
  multi-key config extension.
- Keep `qaffd --short-cid-len` equal to `QAFF_CID_PROFILE_V1_LEN` when using
  v1 CIDs for 1-RTT short headers.
- Do not reuse a worker ID while live CIDs still point to the old worker.
