# Routable CID Profile v2

Routable profiles are optional. Exact CID registration remains the default and
takes priority. Profile v2 lets the BPF dataplane validate a server CID and
select its embedded worker without maintaining one map entry per CID.

The earlier generationless profile v1 is intentionally unsupported: a stale
v1 CID could become valid for a different socket after worker-ID reuse.

## Layout

`QAFF_CID_PROFILE_V2_LEN` is 12 bytes:

```text
byte 0       high nibble: version = 2
             low nibble: flags, currently 0
byte 1       config_id
bytes 2..3   worker_id, big endian, 16-bit
byte 4       worker generation
bytes 5..7   nonce, big endian, 24-bit
bytes 8..11  keyed tag, big endian, 32-bit
```

`worker_id` must be below `QAFF_WORKER_CAPACITY` (currently 4096), generation
must be in `1..255`, and nonce must fit in 24 bits. Servers should choose a
fresh nonce for each issued CID.

The tag binds the config ID, worker ID, generation, and nonce. It is a compact
BPF-friendly routing-integrity check, not a cryptographic MAC or encryption
scheme. Deployments that do not want worker IDs visible should use opaque CIDs
and exact CID registration.

## API

```c
struct qaff_cid_profile_key key;
uint8_t cid[QAFF_CID_PROFILE_V2_LEN];

qaff_cid_profile_v2_generate(&key,
                             config_id,
                             worker_id,
                             generation,
                             nonce,
                             cid,
                             sizeof(cid));

struct qaff_cid_profile_v2_fields fields;
qaff_cid_profile_v2_parse(&key, cid, sizeof(cid), &fields);
```

The userspace parser validates the encoded tag and bounds. The BPF dataplane
additionally requires the embedded generation to equal the non-zero value in
`qaff_worker_generations` before selecting the worker.

## Embedded Configuration

```c
struct qaff_options options;
qaff_options_init(&options);
options.short_cid_len = QAFF_CID_PROFILE_V2_LEN;
options.cid_profile_v2_enabled = 1;
options.cid_profile_v2_config_id = config_id;
memcpy(options.cid_profile_key, key.bytes, sizeof(options.cid_profile_key));
```

Embedded integrations must durably allocate increasing worker generations.
Reusing a worker ID with the same generation would make its old profile CIDs
valid again.

## qaffd Configuration

Store the 16-byte listener key as 32 hex digits in a file readable only by the
daemon:

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

Profile v2 requires both `--pin-root` and `--state-path`. Pinned maps preserve
live routing state across daemon restarts; the snapshot preserves allocated
generation tombstones across daemon and host restarts. The inline
`--cid-profile-v2-key HEX32` form is intended for tests and local development.

## Operational Notes

- Use a separate key per listener or deployment domain.
- The dataplane accepts one active key/config ID at a time.
- Keep `--short-cid-len` equal to `QAFF_CID_PROFILE_V2_LEN`.
- Exact CID entries have priority over profile routing and are independently
  generation-bound.
- Generation values never wrap. After 255 allocations, retire that worker ID
  for the listener instead of reusing an old generation.
