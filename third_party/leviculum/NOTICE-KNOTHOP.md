# NOTICE для форка KnotHop

Первоисточник: https://codeberg.org/Lew_Palm/Leviculum (автор Lew_Palm).
База форка: `cb814c8513fb59d991c96106f1dcdd5d070cb423`. В публикационную копию включено текущее состояние форка, включая незакоммиченные изменения.
Лицензия Leviculum и этого форка: AGPL-3.0-or-later; см. LICENSE и лицензионные заголовки.

## Коммиты поверх базы

- 9dfdaaa2 packet-channel: optional burst handling, PacketSource::try_recv
- c52db531 path recovery for a tunnel client: forced per-interface path request, link attached interface
- 7102a027 std: packet-channel interface, LinkHandle::send_datagram, drop counters
- eb0ee75c core: hash-free link data, Tunnel datagram context, ring AES-GCM backend
- 7123268a rawg: bulk HDLC and CBC decrypt, per-link send wakes, link GCM v1, send window cap, window-only pacing
- 8a9745d3 make the data-proof binding selectable: token tag (default) or packet hash
- ddc15b8a build: turn on hardware SHA-256 and ARMv8 AES
- e8e88cf8 channel: raise the fast-link window ceiling from 48 to 128
- bc407a11 bind data proofs to the token tag instead of hashing the payload twice
- a124b744 LinkHandle::send: wake on ACK instead of sleeping 50 ms when the window is full
- 9933f64d channel: do not round sub-millisecond pacing up to 1 ms
- 13261d45 byte_channel: make HW_MTU, channel capacity and read buffer tunable
- 3032da10 The registry write counter is per directory and needs no 64-bit atomic
- cff47030 The autoconnect poll hashes endpoints without allocating
- 4ed6833b A host bounds a fetch by the client's limit alone
- 17abb070 The discovery registry is read when it changed, not every second
- d3345917 A cull during peer sync reaches the operator line too
- e6715ef2 A torn propagation-store write is no message to lxmd either
- 7f719aa8 lnpnd opens the message store where lxmd left it
- 042e1723 The propagation store reads every name lxmd writes
- 663f9e9e lnpnd shuts down cleanly on SIGTERM, not only on SIGINT
- 6f7f37e0 The USB task runs the reset plan instead of deciding it
- 13e782b0 The commanded reset gets a plan a host test can check
- 8df95c89 nightly-publish accepts every objcopy the lnflash bundle accepts
- 466c1ddb The forge pipeline stops publishing on its cron
- 61101362 just nightly-publish builds and publishes the nightly from the tested tree
- 0e6bf355 The publish scripts read their credentials from files and can dry-run
- 0ff6b82a The publish gate takes the word of the night that just went green
- 1476a9b9 site-check also checks the READMEs' external URLs
- dc5df09b The install instructions hand out the project's own download address
- b05f090d A relay's packet path shares, borrows and streams instead of copying

## Файлы с незакоммиченными изменениями

- `leviculum-core/src/memory_storage.rs`
- `leviculum-core/src/node/builder.rs`
- `leviculum-core/src/node/link_management.rs`
- `leviculum-core/src/node/mod.rs`
- `leviculum-std/src/api/mod.rs`
- `leviculum-std/src/driver/builder.rs`
- `leviculum-std/src/driver/mod.rs`
- `leviculum-std/src/storage.rs`

Справочные патчи KnotHop находятся в `../../docs/patches/` и являются историческими.
