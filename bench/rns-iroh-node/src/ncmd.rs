//! Команды админа ноде `node.cmd/1` (ADR 0028 §2.6–2.8): батч операций над таблицей прав, журнал `(actor, requestid)`,
//! очередь исходящих команд с повтором до `applied` (в т.ч. через PN), `status.get`/`status.push`, автоматическое знакомство нод.
//! Реализация — методы того же `invite::Core`: у сервера, ПК и телефона обработчик один.

use super::*;
use anyhow::anyhow;
use crate::invite::{now_s, Core};
use crate::lxmf_sync::{self, Target};
use crate::peers::{self, Actor, Applied, Hash, Peers};
use leviculum_lxmf::Message;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MAX_OPS: usize = 24;
/// Команды живут до 7 суток (офлайн-нода получит их с PN, ADR §2.3).
pub const MAX_EXP_S: u64 = 7 * 24 * 3600;
const CLOCK_SKEW_S: u64 = 60;
const MAX_JOURNAL: usize = 512;
const MAX_OUTBOX: usize = 256;
const MAX_REPLY_KEEP: usize = 3000;
const PUSH_EVERY: Duration = Duration::from_secs(600);
const OUTBOX_KEEP_S: u64 = 7 * 24 * 3600;

#[derive(Clone, Debug)]
struct JEntry {
    actor: String,
    rid: String,
    exp: u64,
    reply: String,
}

#[derive(Clone, Debug)]
pub struct OutCmd {
    pub rid: String,
    pub target: Hash,
    pub exp: u64,
    pub content: String,
    pub state: String,
    pub results: serde_json::Value,
    pub updated: u64,
}

pub struct State {
    dir: PathBuf,
    journal: Mutex<Vec<JEntry>>,
    outbox: Mutex<BTreeMap<String, OutCmd>>,
    nodes: Mutex<BTreeMap<String, (u64, serde_json::Value)>>,
    pushed: Mutex<Option<Instant>>,
    enq: Mutex<std::collections::HashMap<String, Instant>>,
}

fn read_json(dir: &Path, name: &str) -> serde_json::Value {
    peers::read_private(&dir.join(name), 2 * 1024 * 1024).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(serde_json::Value::Null)
}

impl State {
    pub fn load(dir: &Path) -> State {
        let journal = read_json(dir, "cmd-journal.json").as_array().map(|a| a.iter().filter_map(|e| Some(JEntry {
            actor: e["a"].as_str()?.into(), rid: e["r"].as_str()?.into(), exp: e["e"].as_u64()?, reply: e["p"].as_str()?.into() })).collect()).unwrap_or_default();
        let outbox = read_json(dir, "cmd-outbox.json").as_array().map(|a| a.iter().filter_map(|e| {
            let c = OutCmd { rid: e["rid"].as_str()?.into(), target: unhex(e["t"].as_str()?).try_into().ok()?, exp: e["exp"].as_u64()?, content: e["c"].as_str()?.into(),
                state: e["s"].as_str()?.into(), results: e["res"].clone(), updated: e["u"].as_u64().unwrap_or(0) };
            Some((c.rid.clone(), c))
        }).collect()).unwrap_or_default();
        let nodes = read_json(dir, "status-cache.json").as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), (v["at"].as_u64().unwrap_or(0), v["status"].clone()))).collect()).unwrap_or_default();
        State { dir: dir.to_path_buf(), journal: Mutex::new(journal), outbox: Mutex::new(outbox), nodes: Mutex::new(nodes), pushed: Mutex::new(None), enq: Mutex::new(Default::default()) }
    }

    fn save_journal(&self, j: &[JEntry]) {
        let v: Vec<_> = j.iter().map(|e| serde_json::json!({"a": e.actor, "r": e.rid, "e": e.exp, "p": e.reply})).collect();
        let _ = crate::lxmf_admin::write_private_atomic(&self.dir.join("cmd-journal.json"), &serde_json::to_vec(&v).unwrap());
    }

    fn save_outbox(&self, o: &BTreeMap<String, OutCmd>) {
        let v: Vec<_> = o.values().map(|c| serde_json::json!({"rid": c.rid, "t": hex(&c.target), "exp": c.exp, "c": c.content, "s": c.state, "res": c.results, "u": c.updated})).collect();
        let _ = crate::lxmf_admin::write_private_atomic(&self.dir.join("cmd-outbox.json"), &serde_json::to_vec(&v).unwrap());
    }

    fn save_nodes(&self, n: &BTreeMap<String, (u64, serde_json::Value)>) {
        let v: serde_json::Map<_, _> = n.iter().map(|(k, (at, s))| (k.clone(), serde_json::json!({"at": at, "status": s}))).collect();
        let _ = crate::lxmf_admin::write_private_atomic(&self.dir.join("status-cache.json"), &serde_json::to_vec(&v).unwrap());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpResult {
    pub state: &'static str,
    pub code: Option<&'static str>,
}

impl OpResult {
    fn ok(a: Applied) -> OpResult {
        OpResult { state: if a == Applied::Changed { "applied" } else { "unchanged" }, code: None }
    }
    fn rej(code: &'static str) -> OpResult {
        OpResult { state: if code == "stale" { "stale" } else { "rejected" }, code: Some(code) }
    }
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"state": self.state, "code": self.code})
    }
}

fn hash_arg(op: &serde_json::Value, k: &str) -> Option<Hash> {
    unhex(op[k].as_str()?).try_into().ok()
}

impl Core {
    /// Применить пакет операций от `actor`. Всё под одним замком таблицы, на диск один раз; ошибка записи откатывает пакет.
    /// Возвращает результаты и признак изменения прав (нужно пересмотреть Link и пересчитать допуск).
    pub fn apply_ops(&self, actor: &Actor, ops: &[serde_json::Value], seq: u64) -> (Vec<OpResult>, bool, Option<serde_json::Value>) {
        let now = now_ms() as u64;
        let mut p = self.peers.lock().unwrap();
        let snap = p.checkpoint();
        let mut changed = false;
        let mut status = None;
        let mut out = Vec::new();
        for op in ops {
            let r = match op["op"].as_str().unwrap_or("") {
                "peer.set" => match (unhex(op["pk"].as_str().unwrap_or("")).try_into(), op["rights"].as_u64()) {
                    (Ok(pk), Some(r)) => p.peer_set(actor, pk, r as u16, op["name"].as_str().unwrap_or(""), seq, now).map(OpResult::ok).unwrap_or_else(OpResult::rej),
                    _ => OpResult::rej("bad_args"),
                },
                "peer.remove" => match hash_arg(op, "hash") {
                    Some(h) => p.peer_remove(actor, &h, seq, now).map(OpResult::ok).unwrap_or_else(OpResult::rej),
                    None => OpResult::rej("bad_args"),
                },
                "peers.revoke_by" => match op["issuer"].as_str() {
                    Some(i) => match p.revoke_by(actor, i, seq, now) {
                        Ok(n) => OpResult { state: if n > 0 { "applied" } else { "unchanged" }, code: None },
                        Err(e) => OpResult::rej(e),
                    },
                    None => OpResult::rej("bad_args"),
                },
                "invite.add" => match (unhex(op["pid"].as_str().unwrap_or("")).try_into(), unhex(op["key"].as_str().unwrap_or("")).try_into(), op["rights"].as_u64()) {
                    (Ok(pid), Ok(key), Some(r)) => p.invite_add(actor, pid, key, r as u16, op["expires_ms"].as_u64().unwrap_or(peers::INVITE_DEFAULT_MS), now)
                        .map(OpResult::ok).unwrap_or_else(OpResult::rej),
                    _ => OpResult::rej("bad_args"),
                },
                "invite.cancel" => match unhex(op["pid"].as_str().unwrap_or("")).try_into() {
                    Ok(pid) => p.invite_cancel(actor, &pid).map(OpResult::ok).unwrap_or_else(OpResult::rej),
                    _ => OpResult::rej("bad_args"),
                },
                "invite.redeem" => {
                    // знакомство нод: погасить приглашение у ноды `hash` (пин внутри шифрованного LXMF). Только держатель CONFIG на этой ноде.
                    if *actor != Actor::Local && p.authority(actor) & peers::CONFIG == 0 {
                        OpResult::rej("no_authority")
                    } else {
                        match (hash_arg(op, "hash"), unhex(op["pin"].as_str().unwrap_or("")).try_into()) {
                            (Some(h), Ok(pin)) => match self.pending_add(h, pin) { Ok(()) => OpResult { state: "applied", code: None }, Err(e) => OpResult::rej(e) },
                            _ => OpResult::rej("bad_args"),
                        }
                    }
                }
                "config.set" => p.set_config(actor, op["transit_enabled"].as_bool(), op["exit_enabled"].as_bool()).map(OpResult::ok).unwrap_or_else(OpResult::rej),
                "status.get" => {
                    if *actor != Actor::Local && p.authority(actor) & peers::CONFIG == 0 {
                        OpResult::rej("no_authority")
                    } else {
                        status = Some(self.status_page(&p, op["page"].as_u64().unwrap_or(0) as usize));
                        OpResult { state: "applied", code: None }
                    }
                }
                _ => OpResult::rej("unsupported"),
            };
            changed |= r.state == "applied" && !matches!(op["op"].as_str(), Some("status.get") | Some("invite.redeem"));
            out.push(r);
        }
        if changed || ops.iter().any(|o| matches!(o["op"].as_str(), Some("invite.add") | Some("invite.cancel"))) {
            if p.save().is_err() {
                p.restore(snap);
                return (ops.iter().map(|_| OpResult::rej("io")).collect(), false, None);
            }
        }
        (out, changed, status)
    }

    /// Страница статуса ≤ ~7 КиБ: пары хеш/права/by/seq, приглашения без `key`, контакты, роли.
    fn status_page(&self, p: &Peers, page: usize) -> serde_json::Value {
        let full = p.status(now_ms() as u64);
        let peers_all = full["peers"].as_array().cloned().unwrap_or_default();
        const PER: usize = 24;
        let mut v = serde_json::json!({"ver": env!("CARGO_PKG_VERSION"), "me": full["me"], "controllers": full["controllers"], "transit_enabled": full["transit_enabled"], "exit_enabled": full["exit_enabled"],
            "page": page, "peers_total": peers_all.len(), "peers": peers_all.iter().skip(page * PER).take(PER).cloned().collect::<Vec<_>>()});
        if page == 0 {
            v["invites"] = full["invites"].clone();
            v["contacts"] = full["contacts"].clone();
        }
        while v.to_string().len() > crate::lxmf_admin::MAX_ADMIN_CONTENT - 1024 {
            if let Some(a) = v["peers"].as_array_mut() { if a.pop().is_none() { break; } } else { break; }
        }
        v
    }

    // -------------------------------------------------------------------------------------------- приём

    pub(crate) fn on_cmd(&self, m: &Message) {
        if m.content.len() > crate::lxmf_admin::MAX_ADMIN_CONTENT || !self.rate_cmd.lock().unwrap().allow(m.source_hash) {
            return;
        }
        let Ok(j) = serde_json::from_slice::<serde_json::Value>(&m.content) else { return };
        if j["v"].as_u64() != Some(1) {
            return;
        }
        if j["state"].is_string() {
            self.on_cmd_reply(m, &j);
        } else if j["ops"].is_array() {
            self.on_cmd_request(m, &j);
        }
    }

    fn reply(&self, to: peers::Pk, rid: &str, state: &str, results: &[OpResult], status: Option<serde_json::Value>) -> String {
        let mut r = serde_json::json!({"v": 1, "requestid": rid, "pk": hex(&self.me_pk), "target": hex(&self.me_hash), "state": state, "results": results.iter().map(|x| x.json()).collect::<Vec<_>>()});
        if let Some(s) = status { r["status"] = s; }
        let body = serde_json::to_string(&r).unwrap();
        self.send(lxmf_sync::TITLE_CMD, Target::Pk(to), body.clone().into_bytes(), &format!("cmd:reply:{rid}"), now_s() + 600, true);
        body
    }

    fn on_cmd_request(&self, m: &Message, j: &serde_json::Value) {
        let (Some(rid), Some(exp), Some(seq)) = (j["requestid"].as_str().filter(|r| r.len() == 32 && r.bytes().all(|b| b.is_ascii_hexdigit())), j["exp"].as_u64(), j["seq"].as_u64()) else { return };
        let ops = j["ops"].as_array().unwrap();
        if ops.is_empty() || ops.len() > MAX_OPS || hash_arg(j, "target") != Some(self.me_hash) {
            return;
        }
        // неизвестный источник — молчание; полномочия проверяются при применении
        let Some(pk) = self.peers.lock().unwrap().pk_for_lxmf_source(&m.source_hash) else { return };
        if !crate::lxmf_admin::signed_by_trusted_source(m, &pk) {
            return;
        }
        let Some(actor_hash) = peers::hash_of(&pk) else { return };
        let actor = Actor::Peer(actor_hash);
        if self.peers.lock().unwrap().authority(&actor) == 0 {
            return;
        }
        let now = now_s();
        let actor_s = hex(&actor_hash);
        {
            let j = self.cmd.journal.lock().unwrap();
            if let Some(e) = j.iter().find(|e| e.actor == actor_s && e.rid == rid) {
                // повтор после офлайна: тот же ответ, ничего не применяется заново
                let body = e.reply.clone();
                drop(j);
                self.send(lxmf_sync::TITLE_CMD, Target::Pk(pk), body.into_bytes(), &format!("cmd:reply:{rid}"), now + 600, true);
                return;
            }
        }
        if exp + CLOCK_SKEW_S < now || exp > now + MAX_EXP_S + CLOCK_SKEW_S {
            self.reply(pk, rid, "expired", &[], None);
            return;
        }
        let (results, changed, status) = self.apply_ops(&actor, ops, seq);
        let state = if results.iter().all(|r| matches!(r.state, "applied" | "unchanged")) { "applied" } else if results.iter().any(|r| r.state == "stale") { "stale" } else { "rejected" };
        let body = self.reply(pk, rid, state, &results, status);
        if body.len() <= MAX_REPLY_KEEP || state != "applied" {
            let mut jr = self.cmd.journal.lock().unwrap();
            jr.retain(|e| e.exp + 3600 > now);
            if jr.len() >= MAX_JOURNAL {
                jr.remove(0);
            }
            jr.push(JEntry { actor: actor_s, rid: rid.to_string(), exp, reply: if body.len() <= MAX_REPLY_KEEP { body } else { String::new() } });
            self.cmd.save_journal(&jr);
        }
        if changed {
            self.changed();
            // держатели CONFIG узнают об изменении сразу, не дожидаясь периода (в т.ч. новые роли TRANSIT/EXIT для выбора PN и выхода)
            self.push_status();
        }
    }

    /// Ответ (или `status.push`) от ноды: снимает повтор, сохраняет исход и статус. Подпись — ключом из ответа, сверенным с хешем цели.
    fn on_cmd_reply(&self, m: &Message, j: &serde_json::Value) {
        let Some(pk) = unhex(j["pk"].as_str().unwrap_or("")).try_into().ok().filter(|pk: &peers::Pk| peers::hash_of(pk).map(|h| peers::lxmf_destination(&h)) == Some(m.source_hash)) else { return };
        if !crate::lxmf_admin::signed_by_trusted_source(m, &pk) {
            return;
        }
        let from = peers::hash_of(&pk).unwrap();
        let now = now_s();
        if j["push"].as_bool() == Some(true) {
            // запись статуса принимаем только от ноды, у которой мы известны (контакт/таблица): чужой push — молчание
            if !self.knows(&from) {
                return;
            }
            {
                let mut n = self.cmd.nodes.lock().unwrap();
                if n.len() < 256 || n.contains_key(&hex(&from)) {
                    n.insert(hex(&from), (now, j["status"].clone()));
                    self.cmd.save_nodes(&n);
                }
            }
            self.note_roles(&from, &j["status"]);
            return;
        }
        let Some(rid) = j["requestid"].as_str() else { return };
        let mut ob = self.cmd.outbox.lock().unwrap();
        let Some(c) = ob.get_mut(rid) else { return };
        if c.target != from {
            return;
        }
        lxmf_sync::acknowledged(&self.state, m.source_hash, &format!("cmd:{rid}"));
        if c.state == "pending" {
            c.state = j["state"].as_str().unwrap_or("rejected").to_string();
            c.results = j["results"].clone();
            c.updated = now;
            if j["status"].is_object() {
                {
                    let mut n = self.cmd.nodes.lock().unwrap();
                    n.insert(hex(&from), (now, j["status"].clone()));
                    self.cmd.save_nodes(&n);
                }
                self.note_roles(&from, &j["status"]);
            }
            self.cmd.save_outbox(&ob);
            drop(ob);
            self.changed();
        }
    }

    /// Я управляю нодой `h`: от неё пришёл `status.push`/ответ (она держит меня в CONFIG).
    pub fn manages(&self, h: &Hash) -> bool {
        self.cmd.nodes.lock().unwrap().contains_key(&hex(h))
    }

    /// Роли ноды (TRANSIT/EXIT) из её собственного статуса обновляют контакт: по ним выбираются PN и выходы (подсказка, не полномочие).
    fn note_roles(&self, h: &Hash, status: &serde_json::Value) {
        let roles = (if status["transit_enabled"].as_bool() == Some(true) { peers::TRANSIT } else { 0 }) | (if status["exit_enabled"].as_bool() == Some(true) { peers::EXIT } else { 0 });
        let mut p = self.peers.lock().unwrap();
        // нода, которой я управляю, но ещё не «знаком» (контакта нет): заводим контакт без прав для меня, чтобы роли годились для выбора PN
        let mut created = false;
        if p.contact(h).is_none() {
            if let Some(pe) = p.peer(h).cloned() {
                created = p.contact_set(pe.pk, &pe.name, vec![], "local", 0, roles, now_ms() as u64).is_ok();
            }
        }
        if (p.set_contact_roles(h, roles) || created) && p.save().is_ok() {
            drop(p);
            self.changed();
        }
    }

    fn knows(&self, h: &Hash) -> bool {
        let p = self.peers.lock().unwrap();
        p.peer(h).is_some() || p.contact(h).is_some()
    }

    // -------------------------------------------------------------------------------------------- отправка

    /// Поставить пакет операций ноде `target`. Для самой ноды применяется сразу (владелец). Возвращает requestid.
    pub fn submit(&self, target: Hash, ops: Vec<serde_json::Value>, ttl_s: u64) -> Result<String> {
        if ops.is_empty() || ops.len() > MAX_OPS {
            bail!("пакет: от 1 до {MAX_OPS} операций");
        }
        let mut rid_b = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut rid_b);
        let rid = hex(&rid_b);
        let now = now_s();
        let seq = now_ms() as u64;
        if target == self.me_hash {
            let (res, changed, status) = self.apply_ops(&Actor::Local, &ops, seq);
            let state = if res.iter().all(|r| matches!(r.state, "applied" | "unchanged")) { "applied" } else { "rejected" };
            let mut ob = self.cmd.outbox.lock().unwrap();
            ob.insert(rid.clone(), OutCmd { rid: rid.clone(), target, exp: now, content: String::new(), state: state.into(),
                results: serde_json::json!({"local": true, "r": res.iter().map(|r| r.json()).collect::<Vec<_>>(), "status": status}), updated: now });
            self.cmd.save_outbox(&ob);
            drop(ob);
            if changed {
                self.changed();
            }
            return Ok(rid);
        }
        let exp = now + ttl_s.clamp(60, MAX_EXP_S);
        let body = serde_json::json!({"v": 1, "requestid": rid, "target": hex(&target), "exp": exp, "seq": seq, "ops": ops}).to_string();
        if body.len() > crate::lxmf_admin::MAX_ADMIN_CONTENT {
            bail!("пакет больше {} Б", crate::lxmf_admin::MAX_ADMIN_CONTENT);
        }
        let mut ob = self.cmd.outbox.lock().unwrap();
        ob.retain(|_, c| c.state == "pending" || c.updated + OUTBOX_KEEP_S > now);
        if ob.len() >= MAX_OUTBOX {
            bail!("очередь команд полна");
        }
        ob.insert(rid.clone(), OutCmd { rid: rid.clone(), target, exp, content: body, state: "pending".into(), results: serde_json::Value::Null, updated: now });
        self.cmd.save_outbox(&ob);
        drop(ob);
        self.cmd_tick();
        Ok(rid)
    }

    /// Повторная постановка неподтверждённых команд (идемпотентно: очередь LXMF дедуплицирует по тегу), срок, статус-пуши.
    pub fn cmd_tick(&self) {
        let now = now_s();
        let mut ob = self.cmd.outbox.lock().unwrap();
        let mut dirty = false;
        let mut enq = self.cmd.enq.lock().unwrap();
        for c in ob.values_mut().filter(|c| c.state == "pending") {
            if c.exp <= now {
                c.state = "expired".into();
                c.updated = now;
                dirty = true;
                continue;
            }
            let tag = format!("cmd:{}", c.rid);
            if enq.get(&tag).is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                continue;
            }
            let target = self.peers.lock().unwrap().pk_of_hash(&c.target).map(Target::Pk).unwrap_or(Target::Hash(c.target));
            self.send(lxmf_sync::TITLE_CMD, target, c.content.clone().into_bytes(), &tag, c.exp, false);
            enq.insert(tag, Instant::now());
        }
        enq.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
        drop(enq);
        if dirty {
            self.cmd.save_outbox(&ob);
        }
        drop(ob);
        self.maybe_push();
    }

    /// `status.push` держателям CONFIG раз в 10 мин и после изменений (LXMF, дальше PN).
    pub fn maybe_push(&self) {
        {
            let mut t = self.cmd.pushed.lock().unwrap();
            if t.is_some_and(|x| x.elapsed() < PUSH_EVERY) {
                return;
            }
            *t = Some(Instant::now());
        }
        self.push_status();
    }

    pub fn push_status(&self) {
        let (ctl, status) = {
            let p = self.peers.lock().unwrap();
            (p.controllers(), self.status_page(&p, 0))
        };
        let body = serde_json::json!({"v": 1, "push": true, "state": "status", "pk": hex(&self.me_pk), "target": hex(&self.me_hash), "status": status}).to_string();
        for pk in ctl {
            self.send(lxmf_sync::TITLE_CMD, Target::Pk(pk), body.clone().into_bytes(), "cmd:push", now_s() + 3600, true);
        }
    }

    // -------------------------------------------------------------------------------------------- админ: выпуск и знакомство

    /// Приглашение-стопка для получателя по нодам `grants` (хеш, права принявшего на этой ноде). Для чужих нод
    /// уходит `invite.add` («ожидай»); получатель может гасить сразу — нода, не получившая команду, подождёт повтор.
    pub fn issue_stack(&self, grants: &[(Hash, u16)], ttl_ms: u64) -> Result<(String, Vec<(Hash, String)>)> {
        if grants.is_empty() || grants.len() > crate::invite::MAX_PAIRS {
            bail!("приглашение: от 1 до {} нод", crate::invite::MAX_PAIRS);
        }
        let mut pairs = Vec::new();
        let mut rids = Vec::new();
        for (h, rights) in grants {
            let mut pin = [0u8; 16];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut pin);
            let op = serde_json::json!({"op": "invite.add", "pid": hex(&peers::pin_id(&pin)), "key": hex(&peers::pin_key(&pin)), "rights": rights, "expires_ms": ttl_ms});
            let rid = self.submit(*h, vec![op], MAX_EXP_S)?;
            if *h == self.me_hash {
                let st = self.cmd.outbox.lock().unwrap().get(&rid).map(|c| c.state.clone()).unwrap_or_default();
                if st != "applied" {
                    bail!("приглашение не выпущено на этой ноде: {}", self.cmd.outbox.lock().unwrap().get(&rid).map(|c| c.results.to_string()).unwrap_or_default());
                }
            }
            pairs.push((*h, pin));
            rids.push((*h, rid));
        }
        Ok((crate::invite::encode(&pairs)?, rids))
    }

    /// Автоматическое знакомство (§2.7): для каждой упорядоченной пары (A, B) — `invite.add` на A и `invite.redeem {A, pin}` на B.
    /// Батчи по нодам, срок до 7 суток; ноды гасят приглашения друг у друга сами, админу быть в сети не нужно.
    pub fn introduce(&self, nodes: &[Hash], rights: u16, ttl_ms: u64) -> Result<Vec<(Hash, String)>> {
        if nodes.len() < 2 || nodes.len() > 12 {
            bail!("знакомство: от 2 до 12 нод");
        }
        let mut per: BTreeMap<Hash, Vec<serde_json::Value>> = nodes.iter().map(|h| (*h, Vec::new())).collect();
        for a in nodes {
            for b in nodes.iter().filter(|b| *b != a) {
                let mut pin = [0u8; 16];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut pin);
                per.get_mut(a).unwrap().push(serde_json::json!({"op": "invite.add", "pid": hex(&peers::pin_id(&pin)), "key": hex(&peers::pin_key(&pin)), "rights": rights, "expires_ms": ttl_ms}));
                per.get_mut(b).unwrap().push(serde_json::json!({"op": "invite.redeem", "hash": hex(a), "pin": hex(&pin)}));
            }
        }
        let mut out = Vec::new();
        for (h, ops) in per {
            for chunk in ops.chunks(MAX_OPS) {
                out.push((h, self.submit(h, chunk.to_vec(), MAX_EXP_S)?));
            }
        }
        Ok(out)
    }

    pub fn outbox_view(&self) -> serde_json::Value {
        let ob = self.cmd.outbox.lock().unwrap();
        serde_json::Value::Array(ob.values().map(|c| serde_json::json!({"rid": c.rid, "target": hex(&c.target), "state": c.state, "exp": c.exp, "updated": c.updated, "results": c.results})).collect())
    }

    pub fn nodes_view(&self) -> serde_json::Value {
        let n = self.cmd.nodes.lock().unwrap();
        serde_json::Value::Object(n.iter().map(|(k, (at, s))| (k.clone(), serde_json::json!({"at": at, "status": s}))).collect())
    }

    /// Одно JSON-представление для CLI и приложения: я, таблица, контакты, приглашения, ожидающие пары, очередь команд, статусы нод.
    pub fn view(&self) -> serde_json::Value {
        let mut v = self.peers.lock().unwrap().status(now_ms() as u64);
        v["pending"] = self.pending_view();
        v["outbox"] = self.outbox_view();
        v["nodes"] = self.nodes_view();
        v
    }
}


// ------------------------------------------------------------------------------------------------ локальный владелец

fn grant_arg(j: &serde_json::Value) -> Option<(Hash, u16)> {
    Some((unhex(j["hash"].as_str()?).try_into().ok()?, j["rights"].as_u64()? as u16))
}

impl Core {
    /// Команда локального владельца (процесс/CLI/приложение на самой ноде): JSON-запрос → JSON-ответ. Полномочие даёт доступ
    /// к файлам и сокету ноды, ключа у владельца нет (ADR §1.2). Один исполнитель для CLI и приложения.
    pub fn ctl(&self, req: &serde_json::Value) -> serde_json::Value {
        let ttl_ms = req["ttl_ms"].as_u64().unwrap_or(peers::INVITE_DEFAULT_MS);
        let r: Result<serde_json::Value> = (|| Ok(match req["cmd"].as_str().unwrap_or("") {
            "view" => self.view(),
            "ops" => {
                let target = match req["target"].as_str() { Some(t) => unhex(t).try_into().map_err(|_| anyhow!("target"))?, None => self.me_hash };
                let ops = req["ops"].as_array().cloned().unwrap_or_default();
                let rid = self.submit(target, ops, req["ttl_s"].as_u64().unwrap_or(MAX_EXP_S))?;
                let ob = self.cmd.outbox.lock().unwrap();
                serde_json::json!({"requestid": rid, "state": ob.get(&rid).map(|c| c.state.clone()), "results": ob.get(&rid).map(|c| c.results.clone())})
            }
            "issue" => {
                let grants: Vec<(Hash, u16)> = match req["nodes"].as_array() {
                    Some(a) if !a.is_empty() => a.iter().map(|g| grant_arg(g).ok_or_else(|| anyhow!("nodes[]: hash,rights"))).collect::<Result<_>>()?,
                    _ => vec![(self.me_hash, req["rights"].as_u64().unwrap_or(peers::USE as u64) as u16)],
                };
                let (s, rids) = self.issue_stack(&grants, ttl_ms)?;
                serde_json::json!({"invite": s, "requests": rids.iter().map(|(h, r)| serde_json::json!({"hash": hex(h), "requestid": r})).collect::<Vec<_>>()})
            }
            "introduce" => {
                let nodes: Vec<Hash> = req["nodes"].as_array().ok_or_else(|| anyhow!("nodes"))?.iter().filter_map(|h| unhex(h.as_str()?).try_into().ok()).collect();
                let rights = req["rights"].as_u64().unwrap_or(peers::USE as u64) as u16;
                let rids = self.introduce(&nodes, rights, req["ttl_ms"].as_u64().unwrap_or(peers::INVITE_MAX_MS))?;
                serde_json::json!({"requests": rids.iter().map(|(h, r)| serde_json::json!({"hash": hex(h), "requestid": r})).collect::<Vec<_>>()})
            }
            "join" => {
                let (hs, added) = self.join_stat(req["invite"].as_str().unwrap_or(""))?;
                self.tick();
                serde_json::json!({"nodes": hs.iter().map(|h| hex(h)).collect::<Vec<_>>(), "added": added})
            }
            "contact_remove" => {
                let h: Hash = unhex(req["hash"].as_str().unwrap_or("")).try_into().map_err(|_| anyhow!("hash"))?;
                let mut p = self.peers.lock().unwrap();
                let done = p.contact_remove(&h);
                p.save()?;
                serde_json::json!({"done": done})
            }
            c => bail!("неизвестная команда {c:?}"),
        }))();
        match r {
            Ok(mut v) => {
                if !v.is_object() { v = serde_json::json!({"result": v}); }
                v["ok"] = true.into();
                v
            }
            Err(e) => serde_json::json!({"ok": false, "error": format!("{e:#}")}),
        }
    }

    /// Запросы CLI из `state/ctl/req-*.json` (0600, наш владелец): исполняются здесь, ответ `res-<id>.json`.
    pub fn ctl_poll(&self) {
        let dir = self.state.join("ctl");
        let Ok(rd) = std::fs::read_dir(&dir) else { return };
        for e in rd.flatten().take(8) {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_prefix("req-").and_then(|n| n.strip_suffix(".json")) else { continue };
            if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) { continue; }
            let path = e.path();
            let res = match peers::read_private(&path, 64 * 1024) {
                Ok(Some(b)) => serde_json::from_slice::<serde_json::Value>(&b).map(|r| self.ctl(&r)).unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "json"})),
                _ => serde_json::json!({"ok": false, "error": "запрос нечитаем или права шире 0600"}),
            };
            let _ = std::fs::remove_file(&path);
            let _ = crate::lxmf_admin::write_private_atomic(&dir.join(format!("res-{id}.json")), res.to_string().as_bytes());
        }
    }
}

/// Сторона CLI: положить запрос рядом с работающей нодой и дождаться ответа (до 25 с). Пины и приглашения не попадают в argv.
pub fn ctl_call(state: &Path, req: &serde_json::Value) -> Result<serde_json::Value> {
    let mut idb = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut idb);
    let id = hex(&idb);
    let dir = state.join("ctl");
    let req_path = dir.join(format!("req-{id}.json"));
    let res_path = dir.join(format!("res-{id}.json"));
    crate::lxmf_admin::write_private_atomic(&req_path, req.to_string().as_bytes())?;
    let until = Instant::now() + Duration::from_secs(25);
    while Instant::now() < until {
        if let Some(b) = peers::read_private(&res_path, 256 * 1024)? {
            let _ = std::fs::remove_file(&res_path);
            return Ok(serde_json::from_slice(&b)?);
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let _ = std::fs::remove_file(&req_path);
    bail!("нода не ответила за 25 с (запущена ли она с этим --state?)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite::tests::{deliver, issue_self, node};
    use crate::peers::{CONFIG, USE};

    /// A (админ с CONFIG на S) и сервер S.
    fn pair() -> (crate::invite::tests::Node, crate::invite::tests::Node) {
        let (a, s) = (node("adm", true), node("srv", false));
        let str_ = issue_self(&a.core, USE, peers::INVITE_DEFAULT_MS);
        s.core.join_adopt(&str_, crate::invite::ADOPT_IF_EMPTY).unwrap();
        s.core.tick();
        deliver(&s, &a);
        deliver(&a, &s);
        deliver(&s, &a); // ack
        a.out.lock().unwrap().clear();
        s.out.lock().unwrap().clear();
        (a, s)
    }

    fn outbox_state(n: &crate::invite::tests::Node, rid: &str) -> String {
        n.core.outbox_view().as_array().unwrap().iter().find(|c| c["rid"] == rid).map(|c| c["state"].as_str().unwrap().to_string()).unwrap_or_default()
    }

    #[test]
    fn admin_command_applies_and_reply_closes_outbox() {
        let (a, s) = pair();
        let rid = a.core.submit(s.core.me_hash, vec![serde_json::json!({"op": "config.set", "exit_enabled": true, "transit_enabled": true})], 3600).unwrap();
        assert_eq!(outbox_state(&a, &rid), "pending");
        assert_eq!(deliver(&a, &s), 1);
        assert!(s.core.peers.lock().unwrap().config().exit_enabled && s.core.peers.lock().unwrap().config().transit_enabled);
        // ответ и status.push держателю CONFIG (после изменения ролей)
        assert_eq!(deliver(&s, &a), 2);
        assert_eq!(outbox_state(&a, &rid), "applied");
        assert_eq!(a.core.peers.lock().unwrap().contact(&s.core.me_hash).unwrap().roles, peers::TRANSIT | peers::EXIT, "роли контакта обновлены из статуса ноды");
    }

    #[test]
    fn replay_gets_stored_reply_and_changes_nothing() {
        let (a, s) = pair();
        a.core.submit(s.core.me_hash, vec![serde_json::json!({"op": "config.set", "exit_enabled": true})], 3600).unwrap();
        let sent = a.out.lock().unwrap().clone();
        deliver(&a, &s);
        s.out.lock().unwrap().clear();
        s.core.peers.lock().unwrap().set_config(&Actor::Local, None, Some(false)).unwrap();
        // тот же запрос повторно (задержанная копия с PN): не применяется заново
        *a.out.lock().unwrap() = sent;
        deliver(&a, &s);
        assert!(!s.core.peers.lock().unwrap().config().exit_enabled, "replay не переприменён");
        assert_eq!(s.out.lock().unwrap().len(), 1, "но ответ повторён");
    }

    #[test]
    fn unknown_sender_gets_silence_and_non_admin_is_rejected() {
        let (a, s) = pair();
        let stranger = node("str", false);
        stranger.core.submit(s.core.me_hash, vec![serde_json::json!({"op": "config.set", "exit_enabled": true})], 3600).unwrap();
        deliver(&stranger, &s);
        assert!(s.out.lock().unwrap().is_empty(), "неизвестный источник — молчание");
        // известный без полномочий (пользователь) — rejected
        let user = node("usr", false);
        s.core.peers.lock().unwrap().peer_set(&Actor::Local, user.core.me_pk, USE, "u", 1, 1).unwrap();
        user.core.submit(s.core.me_hash, vec![serde_json::json!({"op": "config.set", "exit_enabled": true})], 3600).unwrap();
        // пользователь не имеет полномочий вообще: тоже молчание (authority == 0)
        deliver(&user, &s);
        assert!(!s.core.peers.lock().unwrap().config().exit_enabled);
        let _ = a;
    }

    #[test]
    fn add_holder_cannot_change_config_or_grant_above_own_rights() {
        let (a, s) = pair();
        let adder = node("adder", false);
        s.core.peers.lock().unwrap().peer_set(&Actor::Local, adder.core.me_pk, USE | peers::ADD, "ad", 5, 5).unwrap();
        let ops = vec![
            serde_json::json!({"op": "config.set", "exit_enabled": true}),
            serde_json::json!({"op": "peer.set", "pk": hex(&node("x", false).core.me_pk), "rights": USE | peers::TRANSIT}),
        ];
        adder.core.submit(s.core.me_hash, ops, 3600).unwrap();
        deliver(&adder, &s);
        let mut m = std::mem::take(&mut *s.out.lock().unwrap());
        assert_eq!(m.len(), 1);
        let r: serde_json::Value = serde_json::from_slice(&m.remove(0).2).unwrap();
        assert_eq!(r["state"], "rejected");
        assert_eq!(r["results"][0]["code"], "no_authority");
        assert_eq!(r["results"][1]["code"], "rights_exceed");
        assert!(!s.core.peers.lock().unwrap().config().exit_enabled);
        let _ = a;
    }

    #[test]
    fn expired_command_is_answered_expired_and_not_applied() {
        let (a, s) = pair();
        let body = serde_json::json!({"v":1,"requestid":hex(&[7u8;16]),"target":hex(&s.core.me_hash),"exp":now_s()-3600,"seq":now_ms() as u64,"ops":[{"op":"config.set","exit_enabled":true}]});
        let m = Message::create(peers::lxmf_destination(&s.core.me_hash), peers::lxmf_destination(&a.core.me_hash), &a.identity, 1.0, lxmf_sync::TITLE_CMD.to_vec(), serde_json::to_vec(&body).unwrap(), vec![], leviculum_lxmf::DeliveryMethod::Direct).unwrap();
        s.core.on_message(&m);
        let out = s.out.lock().unwrap().clone();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&out[0].2).unwrap()["state"], "expired");
        assert!(!s.core.peers.lock().unwrap().config().exit_enabled);
    }

    #[test]
    fn invite_add_and_stack_for_user_across_nodes_then_user_redeems() {
        let (a, s) = pair();
        let user = node("phone-user", true);
        // админ выпускает стопку: на себе и на S (S получает invite.add)
        let (string, rids) = a.core.issue_stack(&[(a.core.me_hash, USE), (s.core.me_hash, USE)], peers::INVITE_DEFAULT_MS).unwrap();
        assert_eq!(rids.len(), 2);
        deliver(&a, &s);
        deliver(&s, &a);
        assert!(a.core.outbox_view().as_array().unwrap().iter().all(|c| c["state"] == "applied"));
        user.core.join(&string).unwrap();
        user.core.tick();
        deliver(&user, &a);
        deliver(&user, &s);
        assert_eq!(a.core.peers.lock().unwrap().rights(&user.core.me_hash), USE);
        assert_eq!(s.core.peers.lock().unwrap().rights(&user.core.me_hash), USE);
        deliver(&a, &user);
        deliver(&s, &user);
        assert!(!user.core.has_pending());
        assert_eq!(user.core.peers.lock().unwrap().contact_list().len(), 2);
    }

    #[test]
    fn ctl_issue_works_for_own_node_alone_and_mixed_with_managed_and_foreign_limits() {
        let (a, s) = pair();
        // только своя нода (нет других узлов): применяется сразу, строка из одной пары
        let r = a.core.ctl(&serde_json::json!({"cmd": "issue", "nodes": [{"hash": hex(&a.core.me_hash), "rights": USE}]}));
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(crate::invite::decode(r["invite"].as_str().unwrap()).unwrap().len(), 1);
        assert_eq!(a.core.peers.lock().unwrap().invite_list().iter().filter(|i| i.state == peers::InviteState::Open).count(), 1);
        // смесь: своя + управляемая S, у каждой свой пин; для S уходит «ожидай»
        let r = a.core.ctl(&serde_json::json!({"cmd": "issue", "nodes": [
            {"hash": hex(&a.core.me_hash), "rights": USE}, {"hash": hex(&s.core.me_hash), "rights": USE}]}));
        assert_eq!(r["ok"], true, "{r}");
        let pairs = crate::invite::decode(r["invite"].as_str().unwrap()).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_ne!(pairs[0].1, pairs[1].1, "пины разные");
        assert_eq!(r["requests"].as_array().unwrap().len(), 2);
        assert_eq!(deliver(&a, &s), 1, "ожидай ушло только чужой ноде");
        // чужая нода сама отказывает выше прав актора: у ADD-держателя нет CONFIG
        s.out.lock().unwrap().clear();
        let adder = node("adder2", false);
        s.core.peers.lock().unwrap().peer_set(&Actor::Local, adder.core.me_pk, USE | peers::ADD, "ad", 5, 5).unwrap();
        let rid = adder.core.submit(s.core.me_hash, vec![serde_json::json!({"op": "invite.add", "pid": hex(&[1u8; 8]), "key": hex(&[2u8; 32]), "rights": peers::CONFIG | USE})], 3600).unwrap();
        deliver(&adder, &s);
        let out = std::mem::take(&mut *s.out.lock().unwrap());
        let rep: serde_json::Value = serde_json::from_slice(&out[0].2).unwrap();
        assert_eq!(rep["results"][0]["code"], "rights_exceed", "{rep} {rid}");
    }

    #[test]
    fn introduce_makes_mutual_peers_without_admin_after_queueing() {
        // админ + три сервера; админ имеет CONFIG на каждом
        let adm = node("adm2", true);
        let srv: Vec<_> = (0..3).map(|i| node(&format!("s{i}"), false)).collect();
        for s in &srv {
            let st = issue_self(&adm.core, USE, peers::INVITE_DEFAULT_MS);
            s.core.join_adopt(&st, crate::invite::ADOPT_IF_EMPTY).unwrap();
            s.core.tick();
            deliver(s, &adm);
            deliver(&adm, s);
        }
        let hs: Vec<Hash> = srv.iter().map(|s| s.core.me_hash).collect();
        let rids = adm.core.introduce(&hs, USE, peers::INVITE_MAX_MS).unwrap();
        assert_eq!(rids.len(), 3, "один пакет на ноду");
        for s in &srv {
            deliver(&adm, s);
        }
        // админа больше нет: ноды гасят приглашения друг у друга сами
        for _ in 0..3 {
            for s in &srv {
                s.core.tick();
            }
            for a in &srv {
                for b in &srv {
                    if a.core.me_hash != b.core.me_hash {
                        deliver(a, b);
                    }
                }
            }
        }
        for a in &srv {
            for b in &srv {
                if a.core.me_hash != b.core.me_hash {
                    assert_eq!(a.core.peers.lock().unwrap().rights(&b.core.me_hash), USE, "полная сетка");
                    assert!(a.core.peers.lock().unwrap().contact(&b.core.me_hash).is_some());
                }
            }
        }
        let _ = CONFIG;
    }

    #[test]
    fn status_get_is_config_only_and_fits_the_message_limit() {
        let (a, s) = pair();
        for i in 0..60u8 {
            let k = node(&format!("p{i}"), false);
            s.core.peers.lock().unwrap().peer_set(&Actor::Local, k.core.me_pk, USE, &format!("peer-{i}"), 10 + i as u64, 10 + i as u64).unwrap();
        }
        a.core.submit(s.core.me_hash, vec![serde_json::json!({"op": "status.get", "page": 0})], 3600).unwrap();
        deliver(&a, &s);
        let out = s.out.lock().unwrap().clone();
        assert!(out[0].2.len() <= crate::lxmf_admin::MAX_ADMIN_CONTENT);
        deliver(&s, &a);
        let nodes = a.core.nodes_view();
        assert!(nodes[hex(&s.core.me_hash)]["status"]["peers_total"].as_u64().unwrap() >= 60);
    }
}
