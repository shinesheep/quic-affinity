# Implementation Plan

## Phase 1: Local MVP

- Build a C library with CID parsing and CID registration APIs.
- Build an eBPF `sk_reuseport` program that can select a socket from a reuseport group.
- Use a fixed short-header CID length per listener.
- Route long-header packets by CID map first.
- Add tests for QUIC DCID parsing.

## Phase 2: Attach and Smoke Test

- Add a libbpf loader. (Initial API exists; needs socket smoke coverage.)
- Create a multi-worker UDP test server. (Implemented as `reuseport_smoke`.)
- Attach the reuseport BPF program to the socket group. (Implemented; requires privileges to run.)
- Register worker sockets in `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`. (Implemented.)
- Register server CIDs from the test server. (Implemented.)
- Verify source-port rebinding still reaches the original worker. (Implemented for explicit source-port changes, IPv4, IPv6, long headers, and configured-length short headers; skipped on unprivileged machines.)

## Phase 3: Real QUIC Stack Integration

- Pick one first integration target.
- Add an example that registers server-issued CIDs.
- Run a real QUIC connection migration/NAT rebinding test.
- Define the control-plane split between embedded library mode and `qaffd`.

## Phase 4: Routable CID Profile

- Define a BPF-friendly CID profile.
- Add config IDs and rotation.
- Add keyed tag verification outside the verifier-critical path if needed.
