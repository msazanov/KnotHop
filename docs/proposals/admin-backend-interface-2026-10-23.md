# Android admin backend interface — v1

Freeze date: 2026-10-23. This schema matches the current Rust/JNI implementation. It covers direct LXMF node-scoped status and HOST_ACCESS operations; it does not claim private-PN/offline delivery.

## Native bridge and commands

```java
static native String runCLI(String command, String stateDir);
```

`Java_com_knothop_vpn_Native_runCLI` uses an allowlisted in-process Clap argv parser. It never invokes an OS shell or generic executable. The passed `stateDir` overrides command text. Accepted verbs: `admin-view`, `admin-submit`, `admin-status`.

```text
admin-view --state DIR --target NODE_DEST
admin-submit --state DIR --target NODE_DEST --root ROOT --op status.get|rights.grant|rights.revoke --holder HOLDER_IDENTITY_HASH --rights MASK --scope NODE --request-id ID
admin-status --state DIR --request-id ID
```

`NODE_DEST`, `ROOT`, `HOLDER_IDENTITY_HASH`, and `ID` are 16-byte values encoded as 32 hex characters. `--scope NODE` means the exact target identity; it is not a root-wide grant. The Rust side resolves the KnotHop node destination hash to the target identity hash using the authenticated local trust snapshot, verifies `dest_from_pub_tag(pk, "node") == NODE_DEST`, and derives the distinct standard `lxmf.delivery` destination from that identity. No public-key/private-key/PIN/endpoint is accepted from UI argv.

Supported mutation is only node-scoped HOST_ACCESS. The UI sends exactly 64 for both `rights.grant` and `rights.revoke`; ordinary network rights are never changed by these operations. This permits granting by a known holder fingerprint even when participant export is disabled. For compatibility, `rights.grant` may also carry a full current rights mask including 64 and only known bits; when non-64 bits are supplied the target verifies they still equal the holder's current rights (otherwise `stale_rights_snapshot`). `rights.revoke` is exactly 64. Grant requires ADD and a root-authorized node-scoped HOST_ACCESS delegation at the target; revoke requires REMOVE plus that exact scoped authority. The root-signed `HostAccessRecord` delegation to a network admin is target-specific and also supplies that admin's HOST_ACCESS scope there; ordinary membership/foreign self-root is insufficient. Generic Record v1 rejects bit 64 because it has no scope field. `status.get` requires ADD, REMOVE, or CONFIG in the selected root. Unknown rights bits reject the entire request.

## `admin-submit` JSON and status lifecycle

A request is persisted locally in bounded private state before the active client LXMF processor accepts it. `accepted:true,queued:true` means the bounded live LXMF engine accepted the request for direct addressed transmission—not delivery or application. The direct message is signed by LXMF's source identity. There is no local grant/revoke substitute.

```json
{"version":1,"accepted":true,"requestid":"<32 hex>","queued":true,"state":"pending"}
```

If the local VPN/LXMF runtime is not active, the bridge returns `unsupported_offline`; it does not claim queueing. If the sender is active but target is unreachable, the direct LXMF request remains bounded and pending for up to 10 minutes, with no PN or offline mailbox claim. It expires locally and is retried after a client-process restart only while its TTL remains valid.

The target accepts expiration timestamps at most 10 minutes plus 60 seconds ahead of its clock to tolerate bounded client clock skew; already expired requests are rejected. Expiry errors from an authenticated administrator are answered explicitly rather than silently discarded by the rate limiter. The extra minute is tolerance, not a longer client queue TTL.

`admin-status` response:

```json
{"version":1,"requestid":"<32 hex>","target":"<32 hex>","state":"pending|delivered|applied|rejected|stale|expired|applied_not_effective|unknown","durable_ack":false,"result":null}
```

`delivered` is the LXMF direct delivery result only. `applied` is reported only after a target-side authority recheck, atomic durable scoped-record save, durable operation-result journal write, and a signed direct LXMF application response received and verified by the client. The target journal is stored per actor (`admin/server/<actor>/<requestid>.json`; quotas 64 files per actor, 32 actors, 2048 total; pruned by age) and is idempotent on `(LXMF actor identity, requestid)`; a different payload under the same ID gets durable `request_id_conflict`. Only authorized administrators (known identity, accepted root, ADD/REMOVE/CONFIG) get durable entries. Rejections before authorization, `journal_quota_exceeded`, `host_acl_unavailable` and `host_commit_failed` are non-durable and not journaled; `status.get` is answered with `durable_ack:true` but is not journaled. An unreadable journal record for one `(actor, requestid)` yields `state:"unknown"`, `code:"journal_unreadable"`, `durable_ack:false` with no re-execution; other requests are unaffected. `unknown` is never retried automatically.

Mutation replies (`rights.grant`/`rights.revoke`) carry optional `record_committed`, `effective_host_allowed` and `changed`. `effective_host_allowed` is the union of all locally allowed roots for this holder on this node, matching per-Link HOST_ACCESS authorization; `changed` compares that union before and after the operation, not just the selected root. The UI must show "access revoked" only when `effective_host_allowed==false` and "access granted" only when it is `true`. If the signed record was saved but the node's effective decision differs from the intent (for example a delegate's revoke ranked below a root grant, or another allowed root still grants access), the reply is `state:"applied"` with `code:"record_committed_not_effective"` and the client status is `applied_not_effective` (durable). These fields describe authorization at commit/application time, not proof that an OS listener is running or a usable client Link exists. Older replies without these fields remain valid but do not prove that access was granted or revoked. Target-side request expiry is 10 minutes. The target rechecks root anchor, actor identity, authority, exact NODE scope, holder, signed record, and sequence at apply time.

Stable submit rejection strings include: `unsupported_offline`, `lxmf_runtime_not_ready`, `target_not_in_authenticated_snapshot`, `target_identity_unknown`, `target_not_in_selected_root`, `target_identity_destination_mismatch`, `target_capability_unknown`, `target_capability_stale`, `target_no_host_authority`, `target_host_access_unavailable`, `target_authority_changed`, `insufficient_scoped_authority`, `holder_not_known_in_selected_root`, `no_status_authority`, `client_admin_queue_full`, `lxmf_send_queue_full`, `request_id_conflict`, `expired`, `backend_error`. Error responses have `accepted:false`, `queued:false`, and `rejected`.

## `admin-view` and trust projection

Before an authenticated target `status.get` reply, the projection may expose only locally established per-root authority sufficient to bootstrap the read-only query. All mutation capabilities remain false and target state is unknown/stale. After a signed direct target response, the cached message signature and source/target identity binding are revalidated before projection.

```json
{
 "version":1,"target":"<KnotHop NODE destination>",
 "node":{"status":"authenticated|unknown","stale":false},
 "capabilities":{"host_access":true,"admin_commands":true,"status_get":true,"participants_export":true,"rights_grant":true,"rights_revoke":true},
 "effective_authority":{"reason":"authenticated_target_status","authorities":[{"root":"<32 hex>","trusted":true,"scope":"NODE","rights":72,"can_status":true,"can_grant":true,"can_revoke":false,"grantable_rights":64,"revocable_rights":0}]},
 "participants":[{"holder":"<identity hash>","rights":1,"host_access":false}],
 "commands":[]
}
```

Authorities are independent per accepted root; the UI selects a root and the backend rechecks it. Participant export is limited to the selected root and bounded to 12 summaries; no public key, IP, alias, or profile is returned. `capabilities.participants_export` is true only when the selected root is the node's sole network root: the node's own identity (always present in its anchor set) is not counted, so a node enrolled into exactly one administrator root (own + 1) exports, while a node that accepted two or more foreign roots (own + 2) never does; a root other than the sole network root never unlocks the list (rule fixed 26.10 after the ES canary, where counting the own identity disabled export on every enrolled node). The UI must not depend on the list: HOST_ACCESS can be granted or revoked by holder fingerprint (32 hex) with the same fingerprint/scope/root confirmation, and the phone shows its own public identity hash in «Мои права» so an administrator can obtain a holder's fingerprint. A target capability is true only if its local host ACL is configured and ready. A node grants HOST_ACCESS authority only to its own root and to accepted roots listed in the operator-provisioned `<state>/host-policy.json` (JSON v1: `{"v":1,"roots":[{"root":"<32 hex>","max_holders":N}]}`; missing file = no foreign root; malformed or oversized file fails startup; changes apply after restart). Accepting a foreign trust anchor alone does not give it HOST_ACCESS. For such a root `capabilities.host_access` is false with `capabilities.reason:"no_host_authority"` (`authority.reason:"NO_HOST_AUTHORITY"`), mutations are rejected with durable `no_host_authority`, and `admin-submit` fails with `target_no_host_authority` from the cached capabilities. The required operator file is `<state>/host-acl.json`, mode 0600, JSON v1 (`aliases` and `allow` literal IPv4 lists); missing/invalid state makes enforced exit startup fail-closed.

## Runtime boundaries and remaining rollout gates

Direct LXMF is embedded with the upstream `CoreProcessor` hook and `LxmfNode`/`LxmfRouter`; this is not Channel, custom crypto, or a separate daemon. Delivery announces use standard LXMF fields with no VPN/network names or IPs. No PN engine, public/private propagation configuration, multihop offline mailbox, policy.set, shell, reboot, firewall operation, or general CONFIG API is included. Invite remains v3/30 days; no 0019 v4/48-hour behavior is implied.

Verified locally through 24.10: the full actual-manifest `--lib` suite (164 passed, 0 failed, 2 pre-existing ignored), a loopback two-node direct-LXMF transport smoke, stale-write/restart/concurrent-commit regressions, multi-root effective ACK and rate-budget/source-key tests. `TunState::allow()` now returns `Result<Admission, AdmissionError>`; both AUTH_OK paths check it. JNI host check, all 18 Java files and the JVM status formatter compile/pass. These are not a proof of the whole feature: the separate real-NodeCtx/LXMF/TUN E2E run and final candidate cross-build need their own completed reports; APK/device integration is still unverified. Earlier canonical artifacts were pre-security snapshot and debug-signed, not installation candidates.
