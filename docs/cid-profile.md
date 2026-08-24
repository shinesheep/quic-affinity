# Routable CID Profile

Routable profiles are optional. Exact CID registration remains the default and
takes priority. The profile lets the BPF dataplane validate a server CID and
select its embedded worker without maintaining one map entry per CID.

## Layout

`QAFF_CID_PROFILE_LEN` is 16 bytes:

```text
bytes 0..1   fixed profile magic (0xa5, 0x5a)
bytes 2..3   worker_id, big endian, 16-bit
byte 4       worker generation
bytes 5..7   nonce, big endian, 24-bit
bytes 8..15  SipHash-2-4 tag, big endian, 64-bit
```

`worker_id` must be below `QAFF_WORKER_CAPACITY` (currently 4096), generation
must be in `1..255`, and nonce must fit in 24 bits. Servers should choose a
fresh nonce for each issued CID.

The tag binds the magic, worker ID, generation, and nonce under a 128-bit
listener-local key. Deployments that do not want worker IDs visible should use
opaque CIDs and exact CID registration.

## API

```c
struct qaff_cid_profile_key key;
uint8_t cid[QAFF_CID_PROFILE_LEN];

qaff_cid_profile_generate(&key,
                          worker_id,
                          generation,
                          nonce,
                          cid,
                          sizeof(cid));

struct qaff_cid_profile_fields fields;
qaff_cid_profile_parse(&key, cid, sizeof(cid), &fields);
```

The userspace parser validates the encoded tag and bounds. The BPF dataplane
additionally requires the embedded generation to equal the non-zero value in
`qaff_worker_generations` before selecting the worker.

In daemon mode, a successful worker registration returns both the committed
generation and the non-secret active-key fingerprint. The worker must compare
that fingerprint with `qaff_cid_profile_key_fingerprint()` over its locally
provisioned listener key before issuing profile CIDs. qaffd never sends the
secret key over the control socket.

## Embedded Configuration

```c
struct qaff_options options;
qaff_options_init(&options);
options.short_cid_len = QAFF_CID_PROFILE_LEN;
options.cid_profile_enabled = 1;
memcpy(options.cid_profile_key, key.bytes, sizeof(options.cid_profile_key));
qaff_open(&options, &ctx);
qaff_apply_config(ctx);
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
      --short-cid-len 16 \
      --reuseport-bpf-policy replace \
      --pin-root /sys/fs/bpf/quic-affinity/listeners/example \
      --state-path /var/lib/quic-affinity/example.state \
      --cid-profile-key-file /etc/quic-affinity/profile.key
```

The profile requires both `--pin-root` and `--state-path`. Pinned maps preserve
live routing state across daemon restarts; the snapshot preserves allocated
generation tombstones across daemon and host restarts. The inline
`--cid-profile-key HEX32` form is intended for tests and local development.

## Operational Notes

- Use a separate key per listener or deployment domain.
- The dataplane accepts one active key at a time.
- Rekeying is drain-only: qaffd refuses profile enablement or key changes while
  durable worker generations exist. Unregister every worker before rotating.
- Keep `--short-cid-len` equal to `QAFF_CID_PROFILE_LEN`.
- The two-byte magic reserves the profile namespace. Once it matches, failed
  profile validation falls back and never downgrades to passive routing.
- Exact CID entries have priority over profile routing and are independently
  generation-bound.
- Generation values never wrap. After 255 allocations, retire that worker ID
  for the listener instead of reusing an old generation.
