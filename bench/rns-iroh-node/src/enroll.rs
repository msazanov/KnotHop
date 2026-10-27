//! ADR 0019: bounded signed invitations, node-scoped evidence and durable first-close.
//! No pin in filenames/state. Link RPC and LXMF integration live in enroll_net.rs.
use crate::{Identity, now_ms};
use crate::trust::{self, Trust, Record, Pk, Hash};
use anyhow::{Result, bail, Context};
use sha2::{Digest, Sha256};
use rand_core::RngCore;
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

pub const TTL: u64 = 48 * 3600;
pub const CAP: u16 = trust::USE | trust::TRANSIT | trust::EXIT;
pub const MAX_WIRE: usize = 16 * 1024;
pub const MAX_NODES: usize = 8;
/// Запас после `expires` перед удалением файлов выдачи (сдвиг часов); дольше погасить приглашение нельзя.
const GC_MARGIN: u64 = 24 * 3600;

pub(crate) fn hex(b: &[u8]) -> String { b.iter().map(|b| format!("{b:02x}")).collect() }
pub(crate) fn raw(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 || s.len() > MAX_WIRE * 2 { bail!("bad hex length") }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i+2).unwrap_or(""), 16).map_err(Into::into)).collect()
}
fn digest(domain: &[u8], data: &[u8]) -> [u8;32] { Sha256::digest([domain,data].concat()).into() }
fn sign(id: &Identity, domain: &[u8], data: &[u8]) -> Result<[u8;64]> {
    id.sign(&[domain,data].concat()).map_err(|e| anyhow::anyhow!("sign: {e:?}"))
}
fn verify(pk: &Pk, domain: &[u8], data: &[u8], sig: &[u8;64]) -> bool {
    Identity::from_public_key_bytes(pk).ok().and_then(|i| i.verify(&[domain,data].concat(), sig).ok()) == Some(true)
}
fn hash(pk: &Pk) -> Result<Hash> { trust::hash_of(pk).ok_or_else(||anyhow::anyhow!("bad identity")) }
fn sorted(nodes: &[Hash]) -> bool { !nodes.is_empty() && nodes.len() <= MAX_NODES && nodes.windows(2).all(|w| w[0] < w[1]) }
pub fn invite_id(pin: &[u8;24]) -> Hash { digest(b"knothop-invite-id-v1", pin)[..16].try_into().unwrap() }
fn pin_hash(pin: &[u8;24]) -> [u8;32] { digest(b"knothop-enroll-pin-v1", &[invite_id(pin).as_slice(), pin].concat()) }
fn same(a: &[u8], b: &[u8]) -> bool { a.len() == b.len() && a.iter().zip(b).fold(0u8, |v,(a,b)|v|(a^b)) == 0 }

/// Debug deliberately omits this bearer secret.
#[derive(Clone, PartialEq)]
pub struct Invite { pub nodes: Vec<Hash>, pub pin: [u8;24] }
impl Invite {
    pub fn new(mut nodes: Vec<Hash>) -> Result<Self> {
        nodes.sort(); if !sorted(&nodes) { bail!("выберите от 1 до 8 разных нод") }
        let mut pin=[0;24]; rand_core::OsRng.fill_bytes(&mut pin);
        if pin == [0;24] { bail!("random pin failed") }
        Ok(Self { nodes, pin })
    }
    pub fn encode(&self) -> Result<String> {
        use base64::Engine;
        if !sorted(&self.nodes) || self.pin == [0;24] { bail!("неверное приглашение v4") }
        let mut b: Vec<u8> = self.nodes.iter().flatten().copied().collect(); b.extend(self.pin);
        let ck=digest(b"knothop-invite-v4", &b); b.extend(&ck[..4]);
        Ok(format!("kh-{}",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)))
    }
    pub fn parse(text: &str) -> Result<Self> {
        use base64::Engine;
        if text.len()>4096 { bail!("приглашение слишком длинное") }
        let s: String=text.chars().filter(|c|!c.is_whitespace()).collect();
        let tail=s.strip_prefix("kh-").ok_or_else(||anyhow::anyhow!("нужно приглашение kh- v4"))?;
        if tail.len()>208 { bail!("приглашение: нужна версия v4") }
        let b=base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(tail).map_err(|_|anyhow::anyhow!("неверное приглашение v4"))?;
        if b.len()<44 || b.len()>156 || (b.len()-28)%16!=0 { bail!("приглашение: нужна версия v4") }
        let n=(b.len()-28)/16;
        let nodes=b[..16*n].chunks_exact(16).map(|b|b.try_into().unwrap()).collect::<Vec<Hash>>();
        let pin: [u8;24]=b[16*n..16*n+24].try_into().unwrap();
        if !sorted(&nodes) || pin==[0;24] || !same(&digest(b"knothop-invite-v4",&b[..b.len()-4])[..4], &b[b.len()-4..]) { bail!("приглашение повреждено") }
        Ok(Self{nodes,pin})
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Grant { pub root: Hash, pub issuer: Hash, pub id: Hash, pub cap: u16, pub issued: u64, pub expires: u64, pub nodes: Vec<Hash>, pub sig: [u8;64] }
impl Grant {
    fn payload(&self)->Vec<u8> {
        let mut b=vec![1]; b.extend(self.root);b.extend(self.issuer);b.extend(self.id);b.extend(self.cap.to_le_bytes());
        b.extend(self.issued.to_le_bytes());b.extend(self.expires.to_le_bytes());b.push(self.nodes.len() as u8);
        b.extend(self.nodes.iter().flatten());b
    }
    pub fn wire(&self)->Vec<u8>{let mut b=self.payload();b.extend(self.sig);b}
    pub fn parse(b:&[u8])->Result<Self>{
        if b.len()<148 || b.len()>260 || b[0]!=1 {bail!("grant length")}
        let n=b[67] as usize;
        if n==0 || n>8 || b.len()!=132+16*n {bail!("grant nodes")}
        let g=Self{root:b[1..17].try_into()?,issuer:b[17..33].try_into()?,id:b[33..49].try_into()?,cap:u16::from_le_bytes(b[49..51].try_into()?),
            issued:u64::from_le_bytes(b[51..59].try_into()?),expires:u64::from_le_bytes(b[59..67].try_into()?),
            nodes:b[68..68+16*n].chunks_exact(16).map(|b|b.try_into().unwrap()).collect(),sig:b[68+16*n..].try_into()?};
        if !sorted(&g.nodes) || g.cap==0 || g.cap & !CAP !=0 || g.expires<=g.issued || g.expires-g.issued>TTL {bail!("grant bounds")}
        Ok(g)
    }
    pub fn create(id:&Identity,root:Hash,invite:&Invite,cap:u16,now:u64)->Result<Self>{
        let mut g=Self{root,issuer:*id.hash(),id:invite_id(&invite.pin),cap,issued:now,expires:now.checked_add(TTL).context("time")?,nodes:invite.nodes.clone(),sig:[0;64]};
        g.sig=sign(id,b"knothop-enroll-grant-v1",&g.payload())?; Self::parse(&g.wire())
    }
    pub fn digest(&self)->[u8;32]{digest(b"knothop-enroll-grant-digest-v1",&self.wire())}
    pub fn fresh(&self,now:u64)->bool{self.issued<=now.saturating_add(3600)&&now<self.expires}
    pub fn verify(&self,tr:&Trust,admin:&Pk)->Result<u8>{
        if hash(admin)?!=self.issuer || !tr.has_anchor(&self.root) || !verify(admin,b"knothop-enroll-grant-v1",&self.payload(),&self.sig) {bail!("grant signature/root")}
        let rights=tr.rights_in(&self.root,&self.issuer);
        let depth=tr.depth_in(&self.root,&self.issuer).context("grant chain")?;
        if rights & trust::ADD==0 || self.cap & !rights!=0 || depth as usize+2>trust::MAX_DEPTH {bail!("grant authority/depth")}
        Ok(depth+2)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnRec { pub node: Pk,pub root:Hash,pub holder:Pk,pub rights:u16,pub seq:u64,pub scope:Hash,pub consent:[u8;64],pub sig:[u8;64] }
impl EnRec {
    fn payload(&self)->Vec<u8>{let mut b=vec![1];b.extend(self.root);b.extend(self.holder);b.extend(self.rights.to_le_bytes());b.extend(self.seq.to_le_bytes());b.extend(self.scope);b}
    pub fn consent(id:&Identity,g:&Grant,rights:u16)->Result<[u8;64]>{sign(id,b"knothop-enroll-consent-v1",&[g.digest().as_slice(),&id.public_key_bytes(),&rights.to_le_bytes()].concat())}
    pub fn consent_ok(g:&Grant,holder:&Pk,rights:u16,sig:&[u8;64])->bool{
        rights!=0&&rights & !g.cap==0 && verify(holder,b"knothop-enroll-consent-v1",&[g.digest().as_slice(),holder,&rights.to_le_bytes()].concat(),sig)
    }
    pub fn create(node:&Identity,g:&Grant,holder:Pk,rights:u16,consent:[u8;64],now:u64)->Result<Self>{
        if !g.fresh(now/1000)||!g.nodes.contains(node.hash())||!Self::consent_ok(g,&holder,rights,&consent) {bail!("enrollment consent")}
        let mut r=Self{node:node.public_key_bytes(),root:g.root,holder,rights,seq:now,scope:*node.hash(),consent,sig:[0;64]};
        r.sig=sign(node,b"knothop-enroll-rec-v1",&[r.payload(),r.consent.to_vec()].concat())?;Ok(r)
    }
    pub fn wire(&self)->Vec<u8>{[self.node.to_vec(),self.payload(),self.consent.to_vec(),self.sig.to_vec()].concat()}
    pub fn parse(b:&[u8])->Result<Self>{
        if b.len()!=299||b[64]!=1{bail!("enrollment record length")}
        Ok(Self{node:b[..64].try_into()?,root:b[65..81].try_into()?,holder:b[81..145].try_into()?,rights:u16::from_le_bytes(b[145..147].try_into()?),
            seq:u64::from_le_bytes(b[147..155].try_into()?),scope:b[155..171].try_into()?,consent:b[171..235].try_into()?,sig:b[235..].try_into()?})
    }
    pub fn verify(&self,g:&Grant)->Result<()> {
        if self.root!=g.root || self.scope!=hash(&self.node)? || !g.nodes.contains(&self.scope) || self.seq<g.issued.saturating_mul(1000)||self.seq>g.expires.saturating_mul(1000)
            || !Self::consent_ok(g,&self.holder,self.rights,&self.consent) || !verify(&self.node,b"knothop-enroll-rec-v1",&[self.payload(),self.consent.to_vec()].concat(),&self.sig) {bail!("enrollment record signature/scope/consent")}
        Ok(())
    }
}

/// Self-contained evidence. The chain grants ONLY ALL authority to the grant signer;
/// EnRec is never converted into a Record v1. Ordinary records include the serving node's chain.
#[derive(Clone, Debug, PartialEq)]
pub struct Proof { pub root:Pk,pub admin:Pk,pub chain:Vec<Record>,pub grant:Grant,pub rec:EnRec }
impl Proof {
    pub fn wire(&self)->Vec<u8>{
        let g=self.grant.wire();let mut b=vec![1];b.extend(self.root);b.extend(self.admin);b.push(self.chain.len() as u8);
        for r in &self.chain {b.extend(r.wire());}b.extend((g.len() as u16).to_le_bytes());b.extend(g);b.extend(self.rec.wire());b
    }
    pub fn parse(b:&[u8])->Result<Self>{
        if b.len()<132+148+299||b.len()>MAX_WIRE||b[0]!=1{bail!("proof length")}
        let n=b[129] as usize;if n>32 {bail!("proof chain limit")}
        let end=130+n*trust::REC_LEN;
        if end+2>b.len(){bail!("proof chain length")}
        let chain=b[130..end].chunks_exact(trust::REC_LEN).map(|b|Record::parse(b).context("proof chain record")).collect::<Result<Vec<_>>>()?;
        let len=u16::from_le_bytes(b[end..end+2].try_into()?) as usize;
        if end+2+len+299!=b.len(){bail!("proof trailing data")}
        Ok(Self{root:b[1..65].try_into()?,admin:b[65..129].try_into()?,chain,grant:Grant::parse(&b[end+2..end+2+len])?,rec:EnRec::parse(&b[end+2+len..])?})
    }
    pub fn authority(&self,id:&Identity)->Result<Trust>{
        if hash(&self.root)?!=self.grant.root {bail!("proof root")}
        let mut tr=Trust::new(id.clone(),None);tr.add_anchor(&self.root)?;
        for _ in 0..=trust::MAX_DEPTH {for r in &self.chain{if r.root!=self.grant.root{bail!("cross-root proof")};tr.offer(r.clone());}}
        self.grant.verify(&tr,&self.admin)?;self.rec.verify(&self.grant)?;Ok(tr)
    }
    pub fn verify(&self,tr:&Trust)->Result<u8>{
        if !tr.has_anchor(&self.grant.root)||tr.public_key_in(&self.grant.root,&self.grant.root)!=Some(self.root){bail!("proof untrusted root")}
        self.rec.verify(&self.grant)?;self.grant.verify(tr,&self.admin)
    }
}

#[derive(Serialize,Deserialize)]
struct Open { grant:String, root:String, admin:String, chain:Vec<String>, h_store:String }
#[derive(Clone,Serialize,Deserialize)]
pub struct Receipt { pub proof:String, pub closed:String, pub hints:Vec<serde_json::Value> }
#[derive(Serialize,Deserialize)]
struct Spent { proof:String }

pub(crate) fn write(path:&Path,bytes:&[u8])->Result<()> {
    use std::{io::Write,os::unix::fs::OpenOptionsExt};
    let mut salt=[0;16];rand_core::OsRng.fill_bytes(&mut salt);
    let tmp=path.with_extension(format!("{}.tmp",hex(&salt)));
    let result=(||->Result<()>{
        let mut f=std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;f.sync_all()?;std::fs::rename(&tmp,path)?;
        std::fs::File::open(path.parent().context("parent")?)?.sync_all()?;Ok(())
    })();if result.is_err(){let _=std::fs::remove_file(tmp);}result
}
fn read<T:serde::de::DeserializeOwned>(p:&Path)->Result<T>{
    use std::io::Read;let f=std::fs::File::open(p)?;if f.metadata()?.len()>MAX_WIRE as u64*8{bail!("enrollment state too large")}
    let mut b=Vec::new();f.take((MAX_WIRE*8+1) as u64).read_to_end(&mut b)?;if b.len()>MAX_WIRE*8{bail!("enrollment state too large")}
    Ok(serde_json::from_slice(&b)?)
}

pub struct Store { dir:PathBuf }
impl Store {
    pub fn new(state:&Path)->Result<Self>{
        use std::os::unix::fs::PermissionsExt;
        let dir=state.join("enroll");std::fs::create_dir_all(&dir)?;std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700))?;Ok(Self{dir})
    }
    fn path(&self,id:&Hash,ext:&str)->PathBuf{self.dir.join(format!("{}.{}",hex(id),ext))}
    pub fn issue(&self,tr:&Trust,g:&Grant,pin:&[u8;24],admin:&Pk,chain:&[Record],now:u64)->Result<()> {
        g.verify(tr,admin)?;
        if !g.fresh(now)||!g.nodes.contains(&tr.me_hash)||g.id!=invite_id(pin){bail!("issue bounds/node/pin")}
        let root=tr.public_key_in(&g.root,&g.root).context("issue root key")?;
        let value=Open{grant:hex(&g.wire()),root:hex(&root),admin:hex(admin),chain:chain.iter().map(|r|hex(&r.wire())).collect(),h_store:hex(&pin_hash(pin))};
        let p=self.path(&g.id,"json");
        if p.exists(){let old:Open=read(&p)?;if old.grant!=value.grant||old.h_store!=value.h_store{bail!("grant equivocation")};return Ok(())}
        let _=self.gc(now);let mut total=0;let mut root_count=0;
        for f in std::fs::read_dir(&self.dir)?.flatten().filter(|f|f.path().extension().is_some_and(|e|e=="json")).take(2048) {
            let o:Open=read(&f.path())?;let old=Grant::parse(&raw(&o.grant)?)?;
            if old.expires>now&&!self.path(&old.id,"spent").exists(){total+=1;if old.root==g.root{root_count+=1;}}
        }
        if total>=64||root_count>=16{bail!("enrollment quota")}
        write(&p,&serde_json::to_vec(&value)?)
    }
    pub fn lookup(&self,pin:&[u8;24],now:u64)->Result<Proof> {
        let id=invite_id(pin);let o:Open=read(&self.path(&id,"json"))?;
        let g=Grant::parse(&raw(&o.grant)?)?;
        if !g.fresh(now)||!same(&raw(&o.h_store)?,&pin_hash(pin)){bail!("unknown")}
        if let Some(p)=self.spent(&id)? {return Ok(p)}
        Ok(Proof{root:raw(&o.root)?.try_into().map_err(|_|anyhow::anyhow!("root key"))?,admin:raw(&o.admin)?.try_into().map_err(|_|anyhow::anyhow!("admin key"))?,
            chain:o.chain.iter().map(|s|Record::parse(&raw(s)?).context("chain")).collect::<Result<Vec<_>>>()?,grant:g,
            rec:EnRec{node:[0;64],root:[0;16],holder:[0;64],rights:0,seq:0,scope:[0;16],consent:[0;64],sig:[0;64]}})
    }
    pub fn spent(&self,id:&Hash)->Result<Option<Proof>>{
        let p=self.path(id,"spent");if !p.exists(){return Ok(None)}
        let s:Spent=read(&p)?;Ok(Some(Proof::parse(&raw(&s.proof)?)?))
    }
    /// Atomic first-close, across processes. EEXIST always returns the SAME stored object.
    pub fn claim(&self,p:&Proof)->Result<Proof>{
        use std::{io::Write,os::unix::fs::OpenOptionsExt};
        let target=self.path(&p.grant.id,"spent");let mut salt=[0;16];rand_core::OsRng.fill_bytes(&mut salt);
        let tmp=self.dir.join(format!(".{}.tmp",hex(&salt)));
        let result=(||->Result<Proof>{
            let mut f=std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&tmp)?;
            f.write_all(&serde_json::to_vec(&Spent{proof:hex(&p.wire())})?)?;f.sync_all()?;
            match std::fs::hard_link(&tmp,&target){Ok(())=>{std::fs::File::open(&self.dir)?.sync_all()?;Ok(p.clone())},Err(e)if e.kind()==std::io::ErrorKind::AlreadyExists=>self.spent(&p.grant.id)?.context("spent empty"),Err(e)=>Err(e.into())}
        })();let _=std::fs::remove_file(tmp);result
    }
    pub fn close(&self,tr:&Trust,node:&Identity,received:&Proof,now:u64)->Result<Option<Proof>>{
        received.verify(tr)?;
        if !received.grant.fresh(now/1000){bail!("expired close")}
        let o:Open=match read(&self.path(&received.grant.id,"json")){Ok(o)=>o,Err(_)if !self.path(&received.grant.id,"json").exists()=>return Ok(None),Err(e)=>return Err(e)};
        if o.grant!=hex(&received.grant.wire())||!received.grant.nodes.contains(node.hash()){bail!("close grant mismatch")}
        let mut own=received.clone();own.chain=tr.chain_for(&node.public_key_bytes());
        // Preserve the grant signer's chain even if the serving node has an independent chain.
        for r in tr.chain_for(&received.admin){if r.root==received.grant.root&&!own.chain.contains(&r){own.chain.push(r)}}
        own.chain.retain(|r|r.root==received.grant.root);
        own.rec=EnRec::create(node,&received.grant,received.rec.holder,received.rec.rights,received.rec.consent,now)?;
        Ok(Some(self.claim(&own)?))
    }
    pub fn receipts(&self,id:&Hash)->Result<Vec<Receipt>>{let p=self.path(id,"closes");if !p.exists(){return Ok(vec![])}let r:Vec<Receipt>=read(&p)?;if r.len()>8{bail!("receipt quota")};Ok(r)}
    pub fn receipt(&self,id:&Hash,r:Receipt)->Result<()> {
        let proof=Proof::parse(&raw(&r.proof)?)?;let mut all=self.receipts(id)?;
        if !all.iter().any(|x|Proof::parse(&raw(&x.proof).unwrap_or_default()).ok().is_some_and(|p|p.rec.scope==proof.rec.scope)){
            if all.len()>=8{bail!("receipt quota")};all.push(r);write(&self.path(id,"closes"),&serde_json::to_vec(&all)?)?;
        }Ok(())
    }
    /// R-7: удалить файлы истёкших выдач. После `expires` (+`GC_MARGIN`) погасить приглашение уже нельзя (`lookup` и `EnRec::create`
    /// требуют fresh), поэтому `.spent`/`.closes` больше не защищают от повторного погашения. Брошенные временные файлы (>10 мин)
    /// тоже удаляются; нечитаемые файлы не трогаем. Число просматриваемых файлов ограничено.
    pub fn gc(&self,now:u64)->usize{
        let expired=|g:Option<Grant>|g.is_some_and(|g|now>g.expires.saturating_add(GC_MARGIN));
        let mut n=0;
        for f in std::fs::read_dir(&self.dir).into_iter().flatten().flatten().take(4096){
            let p=f.path();let Some(ext)=p.extension().and_then(|e|e.to_str())else{continue};
            let dead=match ext{
                "tmp"=>f.metadata().and_then(|m|m.modified()).ok().and_then(|t|t.elapsed().ok()).is_some_and(|d|d>std::time::Duration::from_secs(600)),
                "json"=>expired(read::<Open>(&p).ok().and_then(|o|Grant::parse(&raw(&o.grant).ok()?).ok())),
                "spent"=>expired(read::<Spent>(&p).ok().and_then(|s|Proof::parse(&raw(&s.proof).ok()?).ok()).map(|p|p.grant)),
                "closes"=>expired(read::<Vec<Receipt>>(&p).ok().and_then(|r|Proof::parse(&raw(&r.first()?.proof).ok()?).ok()).map(|p|p.grant)),
                _=>false};
            if dead&&std::fs::remove_file(&p).is_ok(){n+=1}
        }n
    }
    pub fn recover(&self)->Result<Vec<Proof>>{
        let mut out=vec![];let _=self.gc(now_ms() as u64/1000);for f in std::fs::read_dir(&self.dir)?.flatten().filter(|f|f.path().extension().is_some_and(|e|e=="spent")).take(2048){
            let s:Spent=read(&f.path())?;let p=Proof::parse(&raw(&s.proof)?)?;if p.grant.fresh(now_ms() as u64/1000){out.push(p)}if out.len()>=64{break}
        }Ok(out)
    }
}

pub fn closed(node:&Identity,p:&Proof,dest:Hash)->Result<Vec<u8>>{
    let holder=hash(&p.rec.holder)?;let rh=digest(b"knothop-enroll-rec-hash-v1",&p.rec.wire());
    let sig=sign(node,b"knothop-enroll-closed-v1",&[p.grant.id.as_slice(),&holder,&rh,&node.public_key_bytes(),&dest].concat())?;
    let mut b=vec![1,1];b.extend(p.grant.id);b.extend(holder);b.extend(node.public_key_bytes());b.extend(dest);b.extend(p.rec.wire());b.extend(sig);Ok(b)
}
pub fn verify_closed(b:&[u8],p:&Proof,dest:Hash)->Result<()> {
    if b.len()!=477||b[..2]!=[1,1]||b[2..18]!=p.grant.id||b[18..34]!=hash(&p.rec.holder)?||b[34..98]!=p.rec.node||b[98..114]!=dest||b[114..413]!=p.rec.wire(){bail!("closed binding")}
    let rh=digest(b"knothop-enroll-rec-hash-v1",&p.rec.wire());
    if !verify(&p.rec.node,b"knothop-enroll-closed-v1",&[p.grant.id.as_slice(),&hash(&p.rec.holder)?,&rh,&p.rec.node,&dest].concat(),&b[413..].try_into()?){bail!("closed signature")};Ok(())
}

#[derive(Default)]
pub struct Fail2Ban{pub k:u32,pub last:u64}
impl Fail2Ban{
    pub fn fail(&mut self,now:u64,member:bool)->u64{
        self.k=self.k.saturating_sub((now.saturating_sub(self.last)/60_000).min(u32::MAX as u64) as u32);
        if !member{self.k=self.k.saturating_add(1).min(1000)}self.last=now;500u64.saturating_mul(self.k as u64).saturating_mul(self.k as u64).min(60_000)
    }
    pub fn success(&mut self){self.k=0;self.last=0;}
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id()->Identity{leviculum_std::api::generate_identity()}
    fn fixture()->(Identity,Identity,Identity,Trust,Proof,Invite){
        let (root,node,holder)=(id(),id(),id());let mut tr=Trust::new(root.clone(),None);
        tr.issue(*root.hash(),node.public_key_bytes(),trust::USE|trust::TRANSIT|trust::EXIT).unwrap();
        let inv=Invite::new(vec![*node.hash()]).unwrap();let g=Grant::create(&root,*root.hash(),&inv,trust::USE,now_ms()as u64/1000).unwrap();
        let consent=EnRec::consent(&holder,&g,trust::USE).unwrap();let rec=EnRec::create(&node,&g,holder.public_key_bytes(),trust::USE,consent,now_ms()as u64).unwrap();
        let proof=Proof{root:root.public_key_bytes(),admin:root.public_key_bytes(),chain:tr.chain_for(&node.public_key_bytes()),grant:g,rec};(root,node,holder,tr,proof,inv)
    }
    #[test] fn v4_format_one_and_eight_nodes(){for n in [1,8]{let nodes=(1..=n).map(|i|[i as u8;16]).collect();let inv=Invite::new(nodes).unwrap();let s=inv.encode().unwrap();assert_eq!(s.len(),3+(28+16*n)*4/3+usize::from((28+16*n)*4%3!=0));assert!(Invite::parse(&s).unwrap()==inv);}}
    #[test] fn v4_rejects_unsorted_duplicate_zero_pin(){let mut inv=Invite::new(vec![[1;16],[2;16]]).unwrap();inv.nodes.reverse();assert!(inv.encode().is_err());inv.nodes=vec![[1;16],[1;16]];assert!(inv.encode().is_err());inv.nodes=vec![[1;16]];inv.pin=[0;24];assert!(inv.encode().is_err());}
    #[test] fn v4_rejects_old_and_oversized_text(){for s in ["kh-AA", "kh3-abc","😀"]{assert!(Invite::parse(s).is_err())};assert!(Invite::parse(&"x".repeat(4097)).is_err());}
    #[test] fn v4_rejects_tamper_and_trailing(){let inv=Invite::new(vec![[1;16]]).unwrap();let mut s=inv.encode().unwrap().into_bytes();s[10]=if s[10]==b'A'{b'B'}else{b'A'};assert!(Invite::parse(std::str::from_utf8(&s).unwrap()).is_err());assert!(Invite::parse(&(inv.encode().unwrap()+"AA")).is_err());}
    #[test] fn grant_wire_roundtrip_and_bounds(){let(_,_,_,_,p,_)=fixture();assert_eq!(p.grant.wire().len(),148);assert_eq!(Grant::parse(&p.grant.wire()).unwrap(),p.grant);for cap in [0,8,16,32,64,127]{let mut g=p.grant.clone();g.cap=cap;assert!(Grant::parse(&g.wire()).is_err())}}
    #[test] fn grant_wrong_signature_is_not_ok_false(){let(_,_,_,tr,mut p,_)=fixture();p.grant.sig[0]^=1;assert!(p.grant.verify(&tr,&p.admin).is_err());}
    #[test] fn grant_expiry_and_identity_binding(){let(_,_,_,tr,p,_)=fixture();assert!(!p.grant.fresh(p.grant.expires));assert!(!p.grant.fresh(p.grant.issued.saturating_sub(3601)));assert!(p.grant.verify(&tr,&id().public_key_bytes()).is_err());}
    #[test] fn record_signature_consent_and_scope(){let(_,_,_,tr,p,_)=fixture();assert_eq!(p.rec.wire().len(),299);assert!(p.verify(&tr).is_ok());for field in 0..4{let mut q=p.clone();match field{0=>q.rec.scope=[7;16],1=>q.rec.consent[0]^=1,2=>q.rec.sig[0]^=1,_=>q.rec.rights=trust::EXIT};assert!(q.verify(&tr).is_err());}}
    #[test] fn proof_roundtrip_and_exact_length(){let(_,_,_,_,p,_)=fixture();assert_eq!(Proof::parse(&p.wire()).unwrap(),p);let mut b=p.wire();b.push(0);assert!(Proof::parse(&b).is_err());}
    #[test] fn scoped_rights_never_grant_other_nodes_or_delegation(){let(_,node,holder,mut tr,p,_)=fixture();tr.offer_enrollment(p.clone()).unwrap();assert_eq!(tr.rights_in(&p.grant.root,holder.hash()),0);assert_eq!(tr.rights_at(&p.grant.root,holder.hash(),node.hash()),trust::USE);assert_eq!(tr.rights_at(&p.grant.root,holder.hash(),id().hash()),0);assert!(tr.issue(p.grant.root,holder.public_key_bytes(),trust::USE).is_ok());}
    #[test] fn root_revoke_dominates_scoped_record(){let(root,node,holder,mut tr,p,_)=fixture();tr.offer_enrollment(p.clone()).unwrap();tr.issue(*root.hash(),holder.public_key_bytes(),0).unwrap();assert_eq!(tr.rights_at(root.hash(),holder.hash(),node.hash()),0);}
    #[test] fn scoped_client_checks_exit_endpoint_not_itself(){let(root,node,holder,server,p,_)=fixture();let mut client=Trust::new(holder.clone(),None);client.add_anchor(&root.public_key_bytes()).unwrap();client.offer_enrollment(p.clone()).unwrap();assert!(client.common_with(&node.public_key_bytes(),trust::USE,trust::EXIT,false,true,now_ms()as u64));let mut exit=Trust::new(node.clone(),None);exit.add_anchor(&root.public_key_bytes()).unwrap();for r in server.export_all(){exit.offer(r);}exit.offer_enrollment(p).unwrap();assert!(exit.common_with(&holder.public_key_bytes(),trust::EXIT,trust::USE,true,false,now_ms()as u64));}
    #[test] fn closed_binding_and_bad_signature(){let(_,node,_,_,p,_)=fixture();let dest=[5;16];let mut b=closed(&node,&p,dest).unwrap();assert_eq!(b.len(),477);verify_closed(&b,&p,dest).unwrap();assert!(verify_closed(&b,&p,[6;16]).is_err());b[476]^=1;assert!(verify_closed(&b,&p,dest).is_err());}
    #[test] fn fail2ban_quadratic_decay_and_reset(){let mut b=Fail2Ban::default();assert_eq!(b.fail(0,false),500);for k in 2..=10{assert_eq!(b.fail(k,false),500*k*k)}assert_eq!(b.fail(11,false),60_000);assert_eq!(b.fail(60_011,true),50_000);b.success();assert_eq!(b.k,0);}
    /// R-4: квота проверяется до погашения; место освобождают только записи, которые ничего не дают (подписант выдачи потерял ADD).
    #[test] fn enrollment_quota_evicts_only_dead_records(){
        let(root,node,admin)=(id(),id(),id());let mut tr=Trust::new(root.clone(),None);
        tr.issue(*root.hash(),node.public_key_bytes(),CAP).unwrap();
        tr.issue(*root.hash(),admin.public_key_bytes(),trust::USE|trust::TRANSIT|trust::EXIT|trust::ADD).unwrap();
        let inv=Invite::new(vec![*node.hash()]).unwrap();let g=Grant::create(&admin,*root.hash(),&inv,trust::USE,now_ms()as u64/1000).unwrap();
        let mut chain=tr.chain_for(&node.public_key_bytes());for r in tr.chain_for(&admin.public_key_bytes()){if !chain.contains(&r){chain.push(r)}}
        let holder=id();let consent=EnRec::consent(&holder,&g,trust::USE).unwrap();let rec=EnRec::create(&node,&g,holder.public_key_bytes(),trust::USE,consent,now_ms()as u64).unwrap();
        let p=Proof{root:root.public_key_bytes(),admin:admin.public_key_bytes(),chain,grant:g,rec};
        tr.offer_enrollment(p.clone()).unwrap();tr.test_fill_enrollments(&p,trust::MAX_RECS_PER_ROOT);
        let before=tr.record_count();assert!(!tr.enrollment_room(root.hash()),"all records are live: no eviction, no room");assert_eq!(tr.record_count(),before);
        tr.issue(*root.hash(),admin.public_key_bytes(),0).unwrap(); // корень отзывает подписанта выдачи: его записи мертвы
        assert!(tr.enrollment_room(root.hash()));assert!(tr.record_count()<before);
    }
    #[test] fn store_contains_hash_not_pin_and_repeat_same_record(){let(_,node,_,tr,p,inv)=fixture();let dir=std::env::temp_dir().join(format!("kh-enroll-{}",hex(node.hash())));let store=Store::new(&dir).unwrap();let mut receiver=Trust::new(node.clone(),None);receiver.add_anchor(&p.root).unwrap();for r in tr.export_all(){receiver.offer(r);}store.issue(&receiver,&p.grant,&inv.pin,&p.admin,&p.chain,p.grant.issued).unwrap();let bytes=std::fs::read(store.path(&p.grant.id,"json")).unwrap();assert!(!String::from_utf8_lossy(&bytes).contains(&hex(&inv.pin)));assert!(store.lookup(&inv.pin,p.grant.issued).is_ok());let first=store.claim(&p).unwrap();let mut next=p.clone();next.rec.seq+=1;assert_eq!(store.claim(&next).unwrap(),first);std::fs::remove_dir_all(dir).unwrap();}
    #[test] fn gc_removes_expired_issue_files_only_after_margin(){
        let(_,node,_,tr,p,inv)=fixture();let dir=std::env::temp_dir().join(format!("kh-enroll-gc-{}",hex(node.hash())));let store=Store::new(&dir).unwrap();
        let mut receiver=Trust::new(node.clone(),None);receiver.add_anchor(&p.root).unwrap();for r in tr.export_all(){receiver.offer(r);}
        store.issue(&receiver,&p.grant,&inv.pin,&p.admin,&p.chain,p.grant.issued).unwrap();store.claim(&p).unwrap();
        store.receipt(&p.grant.id,Receipt{proof:hex(&p.wire()),closed:String::new(),hints:vec![]}).unwrap();
        let old=std::time::SystemTime::now()-std::time::Duration::from_secs(700);
        let stale=store.dir.join(format!("{}.abcd.tmp",hex(&p.grant.id)));std::fs::write(&stale,b"x").unwrap();std::fs::File::options().write(true).open(&stale).unwrap().set_modified(old).unwrap();
        std::fs::write(store.dir.join(format!("{}.ef01.tmp",hex(&p.grant.id))),b"x").unwrap();
        let files=||std::fs::read_dir(&store.dir).unwrap().count();
        assert_eq!(files(),5);
        assert_eq!(store.gc(p.grant.expires+GC_MARGIN),1,"only the stale tmp: within TTL + margin the evidence against re-redeem stays");assert_eq!(files(),4);
        assert_eq!(store.gc(p.grant.expires+GC_MARGIN+1),3);assert_eq!(files(),1,"fresh tmp file is kept (<10 min)");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test] fn concurrent_claim_has_one_winner(){let(_,node,_,_,p,_)=fixture();let dir=std::env::temp_dir().join(format!("kh-enroll-race-{}",hex(node.hash())));Store::new(&dir).unwrap();let barrier=std::sync::Arc::new(std::sync::Barrier::new(8));let mut workers=vec![];for _ in 0..8{let(dir,b,mut p)=(dir.clone(),barrier.clone(),p.clone());p.rec.holder=id().public_key_bytes();workers.push(std::thread::spawn(move||{b.wait();Store::new(&dir).unwrap().claim(&p).unwrap().wire()}));}let wins=workers.into_iter().map(|w|w.join().unwrap()).collect::<Vec<_>>();assert!(wins.iter().all(|w|w==&wins[0]));std::fs::remove_dir_all(dir).unwrap();}
    #[test] fn evidence_survives_restart_and_revoke(){let(root,node,holder,_,p,_)=fixture();let dir=std::env::temp_dir().join(format!("kh-enroll-save-{}",hex(node.hash())));std::fs::create_dir_all(&dir).unwrap();let mut t=Trust::new(root.clone(),Some(dir.join("trust.json")));t.offer_enrollment(p).unwrap();t.save().unwrap();let mut restored=Trust::load(root.clone(),&dir).unwrap();assert_eq!(restored.rights_at(root.hash(),holder.hash(),node.hash()),trust::USE);restored.issue(*root.hash(),holder.public_key_bytes(),0).unwrap();restored.save().unwrap();let reloaded=Trust::load(root.clone(),&dir).unwrap();assert_eq!(reloaded.rights_at(root.hash(),holder.hash(),node.hash()),0);std::fs::remove_dir_all(dir).unwrap();}
}
