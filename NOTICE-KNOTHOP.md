# NOTICE для Leviculum (зависимость KnotHop)

Первоисточник: https://codeberg.org/Lew_Palm/Leviculum (автор Lew_Palm).
Используется изменённый форк https://github.com/msazanov/leviculum на коммите `5938c438aa1012bce89aaa950cce8f22aef7ab7d` (см. deploy/leviculum.ref).
База в Cargo.toml: `77c4ff13f59116adaf0190d455b83c286c135066`.
Лицензия Leviculum и форка: AGPL-3.0-or-later; см. LICENSE.

## Коммиты форка поверх базы

- 5938c438 Per-link keepalive override and keepalive telemetry in LinkStats
- 85d136de Guard discovery expiry with worker-side record version check
- ea41ea5c Serialize discovery expiry with local announce generations
- ce13e3e0 Use cipher-aware proofs in Python CBC interop tests
- 358e3aa7 Test async ratchet write retry and per-key permission isolation
- d78f8475 Harden write-behind worker against panics and accounting drift
- 6b233591 Test Python RNS interop for per-cipher proof binding
- da1ad589 Bind link proofs per cipher: CBC to PacketHash, GCM to TokenTag
- bd3568b8 Fix write-behind storage edge cases
- c282202e format bounded datagram and storage paths
- ea6f6dd6 test write-behind disk failure retry semantics
- 41b2ae0e test mode-7 RTT retry interval and bound
- 8cd91c79 bound write-behind and migrate private ratchet permissions
- e4b99bea restore bounded GCM-only LRRTT retries
- 573262a9 reserve dispatch before committing tunnel datagrams
- 8ebd4088 decrypt incoming resource cancel in its Link context
- 2397bb9c test owner-only secret writes with queued public ratchets
- dd112095 test KnotHop channel retry budget of eight
- e9e49dff finish upstream metadata and test constructor adaptations
- fd26b972 adapt fork call sites to upstream millisecond and peer APIs
- d71322d3 retain KnotHop channel retry budget of eight
- c248b893 fix Tunnel clock units after upstream millisecond migration
- abe1238d rename rawg to knothop (GCM HKDF info, comments)
- 809a5c29 std: write-behind queue for known ratchets and discovery records off the engine thread (knothop W72)
- 382fb160 knothop waves W41-W69: per-link cipher pair with proof binding, optional CBC link accept, first-hop timeout, cached path-expiry minimum; std api/driver glue
- 76f36d8f packet-channel: optional burst handling, PacketSource::try_recv
- a2587442 path recovery for a tunnel client: forced per-interface path request, link attached interface
- 55d7fbc4 std: packet-channel interface, LinkHandle::send_datagram, drop counters
- e6af074f core: hash-free link data, Tunnel datagram context, ring AES-GCM backend
- 8038a9e2 rawg: bulk HDLC and CBC decrypt, per-link send wakes, link GCM v1, send window cap, window-only pacing
- e4305a19 build: turn on hardware SHA-256 and ARMv8 AES
- 4e342490 channel: raise the fast-link window ceiling from 48 to 128
- fa4e8f73 make the data-proof binding selectable: token tag (default) or packet hash
- a4b3d477 bind data proofs to the token tag instead of hashing the payload twice
- 33f389c5 LinkHandle::send: wake on ACK instead of sleeping 50 ms when the window is full
- b14f3e01 channel: do not round sub-millisecond pacing up to 1 ms
- 92fe2b75 byte_channel: make HW_MTU, channel capacity and read buffer tunable
