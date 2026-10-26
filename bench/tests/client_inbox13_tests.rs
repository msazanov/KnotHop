//! Narrow tests of the production client consumer (not a second implementation).
use super::*;
use std::cell::Cell;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

struct Lab {
    path: PathBuf,
    id: Identity,
    holder: Identity,
    exit: Identity,
    live: trust::Trust,
}

impl Lab {
    fn new() -> Self {
        // /tmp/opencode is root-owned in this harness; use the user's disk cache.
        let base = PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/knothop-tests");
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join(format!("client-inbox13-{:016x}", rand_core::OsRng.next_u64()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let id = leviculum_std::api::generate_identity();
        let holder = leviculum_std::api::generate_identity();
        let exit = leviculum_std::api::generate_identity();
        let mut live = trust::Trust::new(id.clone(), Some(path.join("trust.json")));
        live.issue(*id.hash(), holder.public_key_bytes(), trust::ALL).unwrap();
        live.issue(*id.hash(), exit.public_key_bytes(), trust::USE | trust::TRANSIT | trust::EXIT).unwrap();
        live.save().unwrap();
        Self { path, id, holder, exit, live }
    }

    fn queued_revoke(&self) -> trust::Record {
        let mut cli = trust::Trust::load(self.id.clone(), &self.path).unwrap();
        let r = cli.issue(*self.id.hash(), self.holder.public_key_bytes(), 0).unwrap();
        put_inbox13(&self.path, &r).unwrap();
        r
    }

    fn count(&self, ext: &str) -> usize {
        std::fs::read_dir(self.path.join("inbox13")).unwrap()
            .flatten().filter(|e| e.path().extension().is_some_and(|x| x == ext)).count()
    }

    fn disk_rights(&self) -> u16 {
        trust::Trust::load(self.id.clone(), &self.path).unwrap().rights_in(self.id.hash(), self.holder.hash())
    }
}

impl Drop for Lab {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.path); } // exact test-created directory only
}

#[test]
fn client_inbox13_atomic_private_queue_is_not_cli_trust_commit() {
    let l = Lab::new();
    l.queued_revoke();
    assert_eq!(l.count("rec"), 1);
    assert_eq!(l.count("tmp"), 0);
    assert_eq!(std::fs::metadata(l.path.join("inbox13")).unwrap().mode() & 0o777, 0o700);
    for p in local_inbox_paths(&l.path).unwrap() {
        assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        assert_eq!(read_local_inbox_record(&p).unwrap().rights, 0);
    }
    assert_eq!(l.live.rights_in(l.id.hash(), l.holder.hash()), trust::ALL);
    assert_eq!(l.disk_rights(), trust::ALL);
}

#[test]
fn client_inbox13_live_offer_save_before_send_and_dequeue() {
    let mut l = Lab::new();
    let rec = l.queued_revoke();
    let p = local_inbox_paths(&l.path).unwrap().pop().unwrap();
    let saved = Cell::new(false);
    let mut sent = 0;
    let id = l.id.clone();
    let dir = l.path.clone();
    let holder = *l.holder.hash();
    let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(),
        Some(&l.exit.public_key_bytes()), |tr| {
            assert!(p.exists());
            assert_eq!(tr.rights_in(id.hash(), &holder), 0);
            tr.save()?;
            saved.set(true);
            Ok(())
        }, |wire| {
            assert!(saved.get());
            assert!(p.exists(), "dequeue must follow send and durable save");
            assert_eq!(trust::Trust::load(id.clone(), &dir).unwrap().rights_in(id.hash(), &holder), 0);
            assert_eq!(wire.seq, rec.seq);
            assert_eq!(wire.rights, 0);
            sent += 1;
            true
        }).unwrap();
    assert!(stats.changed);
    assert_eq!((stats.committed, stats.sent, sent), (1, 1, 1));
    assert!(!p.exists());
    assert_eq!(l.live.rights_in(l.id.hash(), l.holder.hash()), 0);
    assert_eq!(l.disk_rights(), 0);
}

#[test]
fn client_inbox13_save_failure_retains_record_and_stale_retry_commits() {
    let mut l = Lab::new();
    l.queued_revoke();
    let mut progress = ClientInboxProgress::default();
    let stats = client_inbox_step(&l.path, &mut l.live, &mut progress, Some(&l.exit.public_key_bytes()),
        |_| bail!("injected save failure"), |_| panic!("must not send before save")).unwrap();
    assert!(stats.changed && stats.save_failed);
    assert_eq!((stats.committed, stats.sent, stats.retained), (0, 0, 1));
    assert_eq!(l.disk_rights(), trust::ALL);
    assert_eq!(l.live.rights_in(l.id.hash(), l.holder.hash()), 0, "failed save must not restore a grant in memory");
    assert_eq!(l.count("rec"), 1);
    let retry = client_inbox_step(&l.path, &mut l.live, &mut progress, Some(&l.exit.public_key_bytes()),
        trust::Trust::save, |_| true).unwrap();
    assert!(!retry.changed, "second offer is Stale but still must save");
    assert_eq!((retry.committed, retry.sent), (1, 1));
    assert_eq!(l.disk_rights(), 0);
    assert_eq!(l.count("rec"), 0);
}

#[test]
fn client_inbox13_actual_filesystem_save_failure_does_not_dequeue() {
    let mut l = Lab::new();
    l.queued_revoke();
    let original = l.path.join("trust.json");
    let backup = l.path.join("trust.saved");
    std::fs::rename(&original, &backup).unwrap();
    std::fs::create_dir(&original).unwrap(); // atomic Trust::save rename must fail, even as root
    let mut progress = ClientInboxProgress::default();
    let failed = client_inbox_step(&l.path, &mut l.live, &mut progress, Some(&l.exit.public_key_bytes()),
        trust::Trust::save, |_| panic!("real save failed")).unwrap();
    assert!(failed.save_failed);
    assert_eq!((failed.sent, failed.retained), (0, 1));
    assert_eq!(l.count("rec"), 1);
    std::fs::remove_dir(&original).unwrap();
    std::fs::rename(&backup, &original).unwrap();
    assert_eq!(l.disk_rights(), trust::ALL);
    let retry = client_inbox_step(&l.path, &mut l.live, &mut progress, Some(&l.exit.public_key_bytes()),
        trust::Trust::save, |_| true).unwrap();
    assert!(!retry.changed);
    assert_eq!((retry.committed, retry.sent), (1, 1));
    assert_eq!(l.disk_rights(), 0);
    assert_eq!(l.count("rec"), 0);
}

#[test]
fn client_inbox13_absent_path_retains_committed_work_without_fsync_loop() {
    let mut l = Lab::new();
    l.queued_revoke();
    let mut progress = ClientInboxProgress::default();
    let one = client_inbox_step(&l.path, &mut l.live, &mut progress, None, trust::Trust::save,
        |_| panic!("no path")).unwrap();
    assert_eq!((one.committed, one.sent, one.retained), (1, 0, 1));
    assert_eq!(l.disk_rights(), 0);
    let two = client_inbox_step(&l.path, &mut l.live, &mut progress, None,
        |_| panic!("unchanged committed offline record must not fsync again"), |_| panic!("no path")).unwrap();
    assert_eq!((two.committed, two.retained), (0, 1));
    let three = client_inbox_step(&l.path, &mut l.live, &mut progress, Some(&l.exit.public_key_bytes()),
        |_| panic!("already saved"), |_| false).unwrap();
    assert_eq!((three.sent, three.retained), (0, 1), "lost admission keeps queue intact");
    let four = client_inbox_step(&l.path, &mut l.live, &mut progress, Some(&l.exit.public_key_bytes()),
        |_| panic!("already saved"), |_| true).unwrap();
    assert_eq!(four.sent, 1);
    assert_eq!(l.count("rec"), 0);
}

#[test]
fn client_inbox13_repeated_and_stale_grant_sends_only_current_revoke() {
    let mut l = Lab::new();
    let old = l.live.export_all().into_iter().find(|r| r.hh == *l.holder.hash()).unwrap();
    let revoke = l.queued_revoke();
    put_inbox13(&l.path, &revoke).unwrap();
    put_inbox13(&l.path, &old).unwrap();
    let mut wires = Vec::new();
    let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(),
        Some(&l.exit.public_key_bytes()), trust::Trust::save, |r| { wires.push(r.clone()); true }).unwrap();
    assert_eq!(stats.committed, 3);
    assert_eq!(wires.len(), 1, "same canonical record is sent once per batch");
    assert_eq!((wires[0].rights, wires[0].seq), (0, revoke.seq));
    assert_eq!(l.disk_rights(), 0);
    assert_eq!(l.count("rec"), 0);
}

#[test]
fn client_inbox13_rejects_bad_parse_signature_future_seq_and_permissions() {
    for kind in 0..4 {
        let mut l = Lab::new();
        let rec = l.queued_revoke();
        let p = local_inbox_paths(&l.path).unwrap().pop().unwrap();
        match kind {
            0 => std::fs::write(&p, b"not hex").unwrap(),
            1 => { let mut b = rec.wire(); *b.last_mut().unwrap() ^= 1; std::fs::write(&p, hex(&b)).unwrap(); },
            2 => {
                let r = trust::Record::sign(&l.id, *l.id.hash(), l.holder.public_key_bytes(), 0, u64::MAX).unwrap();
                std::fs::write(&p, hex(&r.wire())).unwrap();
            },
            _ => std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap(),
        }
        let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(),
            Some(&l.exit.public_key_bytes()), |_| panic!("invalid record must not save"), |_| panic!("invalid record must not send")).unwrap();
        assert_eq!(stats.rejected, 1);
        assert!(!p.exists());
        assert!(p.with_extension("rejected").exists());
        assert_eq!(l.disk_rights(), trust::ALL);
        assert_eq!(l.live.rights_in(l.id.hash(), l.holder.hash()), trust::ALL);
    }
}

#[test]
fn client_inbox13_rejects_foreign_issuer_and_lost_local_authority() {
    let mut l = Lab::new();
    let foreign = leviculum_std::api::generate_identity();
    l.live.issue(*l.id.hash(), foreign.public_key_bytes(), trust::USE).unwrap();
    let forged_local = trust::Record::sign(&foreign, *l.id.hash(), l.holder.public_key_bytes(), 0, now_ms() as u64).unwrap();
    put_inbox13(&l.path, &forged_local).unwrap();
    let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(), None,
        |_| panic!("foreign issuer"), |_| panic!("foreign issuer")).unwrap();
    assert_eq!(stats.rejected, 1);

    let root = leviculum_std::api::generate_identity();
    let mut authority = trust::Trust::new(root.clone(), None);
    let grant = authority.issue(*root.hash(), l.id.public_key_bytes(), trust::ALL).unwrap();
    l.live.add_anchor(&root.public_key_bytes()).unwrap();
    assert_eq!(l.live.offer(grant), trust::Offer::Added);
    let pending = trust::Record::sign(&l.id, *root.hash(), l.holder.public_key_bytes(), trust::USE, now_ms() as u64).unwrap();
    put_inbox13(&l.path, &pending).unwrap();
    let revoked = authority.issue(*root.hash(), l.id.public_key_bytes(), 0).unwrap();
    assert_eq!(l.live.offer(revoked), trust::Offer::Added);
    let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(), None,
        |_| panic!("issuer was revoked before consumption"), |_| panic!("issuer was revoked")).unwrap();
    assert_eq!(stats.rejected, 1);
    assert_eq!(l.count("rejected"), 2);
}

#[test]
fn client_inbox13_wrong_root_exit_cannot_receive_local_record() {
    let mut l = Lab::new();
    l.queued_revoke();
    let other = leviculum_std::api::generate_identity();
    l.live.add_anchor(&other.public_key_bytes()).unwrap();
    let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(),
        Some(&other.public_key_bytes()), trust::Trust::save, |_| panic!("foreign root is not EXIT in record root")).unwrap();
    assert_eq!((stats.committed, stats.sent, stats.retained), (1, 0, 1));
    assert_eq!(l.count("rec"), 1);
}

#[test]
fn client_inbox13_bounds_batch_scan_and_queue_without_discarding_evidence() {
    let mut l = Lab::new();
    for _ in 0..CLIENT_INBOX_BATCH + 1 {
        let holder = leviculum_std::api::generate_identity();
        let r = trust::Record::sign(&l.id, *l.id.hash(), holder.public_key_bytes(), trust::USE, now_ms() as u64).unwrap();
        put_inbox13(&l.path, &r).unwrap();
    }
    let mut progress = ClientInboxProgress::default();
    let count = l.live.record_count();
    let one = client_inbox_step(&l.path, &mut l.live, &mut progress, None, trust::Trust::save, |_| panic!("offline")).unwrap();
    assert_eq!(one.committed, CLIENT_INBOX_BATCH);
    assert_eq!(l.live.record_count(), count + CLIENT_INBOX_BATCH);
    client_inbox_step(&l.path, &mut l.live, &mut progress, None, trust::Trust::save, |_| panic!("offline")).unwrap();
    assert_eq!(l.live.record_count(), count + CLIENT_INBOX_BATCH + 1, "offline early entries must not starve later work");
    for i in local_inbox_paths(&l.path).unwrap().len()..LOCAL_INBOX_LIMIT {
        std::fs::write(l.path.join("inbox13").join(format!("evidence-{i}.rejected")), b"evidence").unwrap();
    }
    let rec = trust::Record::sign(&l.id, *l.id.hash(), l.holder.public_key_bytes(), 0, now_ms() as u64).unwrap();
    assert!(put_inbox13(&l.path, &rec).is_err());
    assert_eq!(local_inbox_paths(&l.path).unwrap().len(), LOCAL_INBOX_LIMIT);
    std::fs::write(l.path.join("inbox13/overflow.rejected"), b"evidence").unwrap();
    assert!(client_inbox_step(&l.path, &mut l.live, &mut progress, None,
        |_| panic!("unbounded scan"), |_| panic!("unbounded scan")).is_err());
    assert_eq!(l.count("rec"), CLIENT_INBOX_BATCH + 1, "never discard pending revocations for quota");
}

#[test]
fn client_inbox13_symlink_rejection_preserves_target_and_existing_evidence() {
    let mut l = Lab::new();
    let rec = l.queued_revoke();
    let p = local_inbox_paths(&l.path).unwrap().pop().unwrap();
    let target = l.path.join("public-evidence");
    std::fs::write(&target, b"must not read or overwrite").unwrap();
    std::fs::remove_file(&p).unwrap();
    std::os::unix::fs::symlink(&target, &p).unwrap();
    let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(), None,
        |_| panic!("symlink"), |_| panic!("symlink")).unwrap();
    assert_eq!(stats.rejected, 1);
    assert_eq!(std::fs::read(&target).unwrap(), b"must not read or overwrite");
    std::fs::write(&p, b"malformed").unwrap();
    let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(), None,
        |_| panic!("malformed"), |_| panic!("malformed")).unwrap();
    assert_eq!(stats.retained, 1, "collision with .rejected must not destroy old evidence");
    assert!(p.exists());
    assert_eq!(rec.rights, 0);
}

#[test]
fn client_inbox13_busy_writer_does_not_block_maintenance_or_remove_work() {
    let mut l = Lab::new();
    l.queued_revoke();
    let writer = open_local_inbox(&l.path, false).unwrap();
    lock_local_inbox(&writer, false).unwrap();
    let stats = client_inbox_step(&l.path, &mut l.live, &mut ClientInboxProgress::default(), None,
        |_| panic!("writer owns lock"), |_| panic!("writer owns lock")).unwrap();
    assert!(!stats.changed);
    assert_eq!(l.count("rec"), 1);
}
