# Fuzzing

quic-affinity provides Clang libFuzzer targets for the three process boundaries
that consume compact, attacker-influenced byte strings:

- `fuzz_quic_parser` exercises long- and short-header DCID parsing and canonical
  BPF map-key construction.
- `fuzz_cid_profile` exercises v1/v2 validation plus generated-value round
  trips.
- `fuzz_control_protocol` exercises request and reply decoding, canonical
  re-encoding, and generated messages for every supported operation.

Build and run the bounded smoke suite with:

```sh
CC=clang cmake -B build-fuzz -S . \
  -DQAFF_BUILD_BPF=OFF \
  -DQAFF_BUILD_DAEMON=OFF \
  -DQAFF_BUILD_TOOLS=OFF \
  -DQAFF_BUILD_EXAMPLES=OFF \
  -DQAFF_BUILD_FUZZERS=ON
cmake --build build-fuzz --parallel 2
ctest --test-dir build-fuzz --output-on-failure -L fuzz
```

The smoke wrapper defaults to 1,000 inputs per target. Set `QAFF_FUZZ_RUNS` to
change that bound. CI builds the harnesses with AddressSanitizer and
UndefinedBehaviorSanitizer and runs the smoke suite on every change.
The bounded harnesses disable LeakSanitizer's exit scan because the exercised
parsers do not allocate heap memory and some ptrace-based runners cannot execute
that scan. The normal sanitizer unit suite retains leak detection; set
`QAFF_FUZZ_DETECT_LEAKS=1` to opt into it for a fuzz run.

For a longer local campaign, keep each target's corpus separate:

```sh
mkdir -p fuzz-corpus/control fuzz-artifacts/control
build-fuzz/fuzz_control_protocol \
  -dict=tests/fuzz/control_protocol.dict \
  -artifact_prefix=fuzz-artifacts/control/ \
  -max_total_time=3600 \
  fuzz-corpus/control
```

`fuzz-corpus/` and `fuzz-artifacts/` are ignored by Git. Minimize and retain a
reproducer before fixing a crash; after fixing it, add the smallest useful
input to a regression test or a reviewed seed corpus. Never commit captures,
production CIDs, credentials, or other sensitive traffic.
