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

## Functional Correctness Remediation

- Make exact CID ownership immutable until explicit retirement, including
  atomic enforcement in the embedded API and cross-process enforcement in
  `qaffd`. (Implemented.)
- Reject replacing an active worker socket while that worker owns exact CIDs;
  preserve daemon restart recovery. (Implemented.)
- Enforce one worker ID per socket cookie and complete passive-egress cookie
  registration in embedded mode. (Implemented.)
- Detect target socket close/replacement continuously in `qaff-agent` and
  re-register without keeping an abandoned listener alive. (Implemented.)
- Add an application-readiness gate so passive egress learning is active before
  the first server response. (Implemented with synchronous, fail-closed
  qaff-agent startup readiness hooks and explicit withdrawal failures.)
- Require durable worker generations when CID profile v2 is enabled.
  (Implemented: qaffd requires both pinned maps and a state snapshot.)
- Make worker unregistration and its persisted snapshot transactional.
- Validate fixed fallback targets and reject conflicting pre-existing
  reuseport BPF programs.

## Pre-release Productionization

- Export an installable CMake package and pkg-config metadata. (Implemented.)
- Make tests, BPF, daemon, tools, and examples independently configurable. (Implemented.)
- Replace the private fixed-struct control transport with an explicitly encoded
  `SOCK_SEQPACKET` protocol. (Implemented.)
- Split qaffd into independently testable protocol, authorization, state,
  worker-registry, and CID-index modules. (Implemented.)
- Add fuzzing, scale tests, fault injection, and arm64 build validation.
  (Parser/profile/control-protocol fuzzing and CID-index scale coverage
  implemented; state-store write/sync/rename fault injection and native arm64
  CI build/test coverage implemented.)
- Add signed release artifacts, checksums, SBOM generation, and native packages.
