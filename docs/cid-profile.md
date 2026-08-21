# Routable CID Profile

This document defines the first QUIC-stack-neutral server CID profile for
`quic-affinity`.

Routable profiles are optional. Existing CID map registration remains valid and
takes priority. When a profile is enabled for a listener, the BPF dataplane can
validate a profile CID and select the embedded worker ID after a CID map miss.
Profile v2 is recommended for new low-state deployments.

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

Deployments that do not want to expose worker IDs should use opaque CIDs plus
explicit CID map registration until an encrypted profile exists.

## v2 Layout

`QAFF_CID_PROFILE_V2_LEN` is 12 bytes:

```text
byte 0       high nibble: version = 2
             low nibble: profile flags, currently 0
byte 1       config_id
bytes 2..3   worker_id, big endian, 16-bit
byte 4       worker generation
bytes 5..7   nonce, big endian, 24-bit
bytes 8..11  keyed tag, big endian, 32-bit
```

The v2 tag is still BPF-friendly rather than a cryptographic MAC, but it raises
the active-forgery space from v1's 16-bit tag to 32 bits and binds config ID,
worker ID, generation, and nonce. BPF also checks that the embedded generation
matches the current `qaff_worker_generations` map entry for the worker. This
prevents stale profile CIDs from routing to a new worker after worker ID reuse.

## API

Generate:

```c
uint8_t cid[QAFF_CID_PROFILE_V1_LEN];
qaff_cid_profile_v1_generate(&key, worker_id, nonce, cid, sizeof(cid));
```

Generate v2:

```c
uint8_t cid[QAFF_CID_PROFILE_V2_LEN];
qaff_cid_profile_v2_generate(&key, config_id, worker_id, generation, nonce, cid, sizeof(cid));
```

Parse:

```c
struct qaff_cid_profile_v1_fields fields;
qaff_cid_profile_v1_parse(&key, cid, cid_len, &fields);
```

There are two valid integration choices.

In low-state mode, enable the v2 listener profile key and issue profile CIDs
without per-CID registration:

```c
struct qaff_options options;
qaff_options_init(&options);
options.short_cid_len = QAFF_CID_PROFILE_V2_LEN;
options.cid_profile_v2_enabled = 1;
options.cid_profile_v2_config_id = config_id;
memcpy(options.cid_profile_v1_key, key.bytes, sizeof(options.cid_profile_v1_key));
```

With `qaffd`, store the same 16-byte listener key as 32 hex digits in a file
readable by the daemon. For regular files, `qaffd` rejects key files that grant
group or other permissions:

```sh
qaffd --socket /tmp/qaffd.sock \
      --bpf /usr/libexec/quic-affinity/qaff_reuseport.bpf.o \
      --short-cid-len 12 \
      --reuseport-bpf-policy replace \
      --pin-root /sys/fs/bpf/quic-affinity/listeners/example \
      --state-path /var/lib/quic-affinity/example.state \
      --cid-profile-v2-key-file /etc/quic-affinity/profile-v2.key \
      --cid-profile-v2-config-id 7
```

qaffd requires both `--pin-root` and `--state-path` when profile v2 is enabled.
The snapshot preserves allocated generation tombstones across daemon and host
restarts, while the pinned maps preserve live dataplane state across daemon
restarts. Embedded integrations must provide equivalent durable generation
allocation themselves before reusing a worker ID.

`--cid-profile-v1-key HEX32` and `--cid-profile-v2-key HEX32` also exist for
tests and local development, but
production deployments should prefer the file form so the key is not exposed in
process arguments.

In compatibility mode, the server may still register generated CIDs through the
normal control API. Explicit CID-map entries have priority over profile routing:

```c
qaff_control_register_cid(control_fd, fields.worker_id, cid, cid_len);
```

## Operational Notes

- Use a separate key per listener or deployment domain.
- The current BPF config accepts one active profile key/config at a time. Key rotation needs a
  drain window using CID registration, a second listener instance, or a future
  multi-key config extension.
- Keep `qaffd --short-cid-len` equal to the active profile length when using
  profile CIDs for 1-RTT short headers.
- Prefer v2 when worker IDs may be reused; v2 generation checks reject stale
  CIDs after worker replacement.
