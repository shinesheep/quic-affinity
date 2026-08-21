# Contributing to quic-affinity

Thank you for helping improve quic-affinity. Changes to the dataplane, control
protocol, authorization, or persisted state can affect live QUIC traffic, so
please keep patches focused and include evidence for correctness.

## Before opening a change

Use a public issue to discuss substantial features, protocol changes, and
behavioral compatibility. Do not report suspected vulnerabilities publicly;
follow [SECURITY.md](SECURITY.md) instead.

On Debian or Ubuntu, a typical development environment can be installed with:

```sh
sudo apt-get install build-essential clang cmake libbpf-dev libcap2-bin \
  libelf-dev pkg-config zlib1g-dev
```

Configure, build, and test with:

```sh
cmake -B build -S . -DQAFF_BUILD_QUICHE_EXAMPLES=OFF
cmake --build build
ctest --test-dir build --output-on-failure
```

For cross compilation, set `QAFF_BPF_TARGET_ARCH` to the libbpf architecture
name and point `QAFF_BPF_SYSTEM_INCLUDE_DIR` at the target directory containing
`asm/types.h`.

Some integration tests need BPF-related kernel capabilities and a compatible
Linux kernel. Their wrappers attempt to apply narrow file capabilities with
passwordless `sudo`; unsupported environments report the test as skipped.
Parser, CID-profile, control-protocol, authorization, state-store, worker
registry, and CID-index unit tests must pass in every environment.
To exercise the unprivileged configuration explicitly, run:

```sh
cmake -B build-no-bpf -S . -DQAFF_BUILD_BPF=OFF
cmake --build build-no-bpf
ctest --test-dir build-no-bpf --output-on-failure
```

Before submitting, also run a strict release build:

```sh
cmake -B build-release -S . \
  -DCMAKE_BUILD_TYPE=Release \
  -DQAFF_BUILD_QUICHE_EXAMPLES=OFF \
  -DCMAKE_C_FLAGS=-Werror
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

## Change expectations

- Follow the existing C11 style and keep compiler warnings enabled.
- Add focused regression tests for bug fixes and boundary cases.
- Document public API, command-line, privilege, protocol, and state-format
  changes in the same pull request.
- Once a compatibility baseline is declared for a release, preserve public
  protocol and state compatibility unless the change includes a migration
  plan. Before that baseline, prefer a clean final design over compatibility
  scaffolding.
- Avoid unrelated formatting or refactoring in behavior changes.
- Never commit private keys, production CIDs, packet captures, credentials, or
  host-specific bpffs state.

By contributing, you agree that your contribution is licensed under the
project's [MIT License](LICENSE).
