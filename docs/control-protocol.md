# qaffd Control Protocol

The qaffd control protocol is private to libqaffinity and the binaries built
from the same source tree. Applications use `quic_affinity/control.h`; they do
not construct protocol packets directly.

The transport is an `AF_UNIX`, `SOCK_SEQPACKET` socket. Every request and reply
is exactly one packet. Worker registration requests carry exactly one UDP
socket through `SCM_RIGHTS`; all other operations reject attached file
descriptors.

## Frame

Every multi-byte integer is unsigned big-endian unless noted otherwise.

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 4 | magic (`0x51414646`, `QAFF`) |
| 4 | 2 | protocol schema identifier |
| 6 | 2 | operation |
| 8 | 4 | status (`0` in requests; errno value in replies) |
| 12 | 4 | payload length |
| 16 | variable | operation-specific payload |

The payload length must exactly match the remainder of the packet. Packets are
limited to 8192 bytes. Truncated packets, trailing bytes, unsupported versions,
invalid field lengths, truncated ancillary data, and multiple passed file
descriptors are rejected.

Requests encode only fields needed by their operation. CID values use a
one-byte length followed by the CID bytes. Worker-list replies contain a next
cursor, total count, page count, and explicitly encoded worker records. Config
paths use a two-byte length and un-terminated path bytes. Error replies have no
payload.

The codec and its process-local semantic message type live in
`src/internal/control_protocol.c` and `src/internal/control_protocol.h`. The decoded structure is not a
wire ABI and must never be sent or received directly.
