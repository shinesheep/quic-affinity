# Implementation Plan

## Phase 1: Local MVP

- Build a C library with CID parsing and CID registration APIs.
- Build an eBPF `sk_reuseport` program that can select a socket from a reuseport group.
- Use a fixed short-header CID length per listener.
- Route long-header packets by CID map first.
- Add tests for QUIC DCID parsing.

## Phase 2: Attach and Smoke Test

- Add a libbpf loader. (Implemented with IPv4/IPv6 socket smoke coverage.)
- Create a multi-worker UDP test server. (Implemented as `reuseport_smoke`.)
- Attach the reuseport BPF program to the socket group. (Implemented; requires privileges to run.)
- Register worker sockets in `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`. (Implemented.)
- Register server CIDs from the test server. (Implemented.)
- Verify source-port rebinding still reaches the original worker. (Implemented for explicit source-port changes, IPv4, IPv6, long headers, and configured-length short headers; skipped on unprivileged machines.)

## Phase 3: Real QUIC Stack Integration

- Pick one first integration target.
- Add an example that registers server-issued CIDs. (Implemented with optional quiche FFI probes.)
- Run a real QUIC connection migration/NAT rebinding test. (Implemented for quiche UDP source-port changes.)
- Define the control-plane split between embedded library mode and `qaffd`. (Implemented.)

## Phase 4: Routable CID Profile

- Define a BPF-friendly CID profile.
- Add config IDs and rotation.
- Add keyed tag verification outside the verifier-critical path if needed.

## Pre-release Productionization

- Export an installable CMake package and pkg-config metadata. (Implemented.)
- Make tests, BPF, daemon, tools, and examples independently configurable. (Implemented.)
- Replace the private fixed-struct control transport with an explicitly encoded
  `SOCK_SEQPACKET` protocol. (Implemented.)
- Split qaffd into independently testable protocol, authorization, state,
  worker-registry, and CID-index modules. (Protocol and authorization modules
  implemented.)
- Add fuzzing, scale tests, fault injection, and arm64 build validation.
- Add signed release artifacts, checksums, SBOM generation, and native packages.
