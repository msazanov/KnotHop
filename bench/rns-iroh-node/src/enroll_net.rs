//! ADR 0019 orchestration. First contact is RNS Link Request/Response; close traffic is LXMF.
use super::*;
use crate::enroll::{self, Invite, Grant, Proof, EnRec, Store, Receipt, Fail2Ban};
use crate::trust::{Trust, Pk, Hash};
use serde::{Serialize,Deserialize};
use std::sync::{OnceLock,Weak};

pub const PATH: &str = "/enroll/v4";
pub const TITLE: &[u8] = b"enroll/4";
static SERVICES: OnceLock<Mutex<HashMap<PathBuf,Weak<Service>>>> = OnceLock::new();
fn state_key(p:&Path)->PathBuf{p.canonicalize().unwrap_or_else(|_|p.into())}
pub fn find(p:&Path)->Option<Arc<Service>>{SERVICES.get()?.lock().ok()?.get(&state_key(p))?.upgrade()}

struct Session { peer:Pk,nonce:[u8;16],proof:Proof,until:Instant,iface:usize }
pub struct Service {
    pub node:Arc<Node>,pub identity:Identity,pub trust:Arc<Mutex<Trust>>,pub state:PathBuf,
    client:Option<Weak<ClientCtx>>,sessions:Mutex<HashMap<LinkId,Session>>,ban:Mutex<Fail2Ban>,
    io:Mutex<()>,rate:Mutex<(VecDeque<Instant>,HashMap<Hash,VecDeque<Instant>>)>,
    inflight:Arc<tokio::sync::Semaphore>, delays:Arc<tokio::sync::Semaphore>,
}
pub fn register(node:Arc<Node>,identity:Identity,trust:Arc<Mutex<Trust>>,state:&Path,client:Option<Weak<ClientCtx>>)->Arc<Service>{
    let s=Arc::new(Service{node,identity,trust,state:state.into(),client,sessions:Mutex::new(HashMap::new()),ban:Mutex::new(Fail2Ban::default()),io:Mutex::new(()),rate:Mutex::new((VecDeque::new(),HashMap::new())),inflight:Arc::new(tokio::sync::Semaphore::new(8)),delays:Arc::new(tokio::sync::Semaphore::new(4))});
    s.node.register_request_handler(DestinationHash::new(dest_from_pub_tag(&s.identity.public_key_bytes(),T13_TAG)),PATH,leviculum_std::api::RequestPolicy::AllowAll);
    SERVICES.get_or_init(Default::default).lock().unwrap().insert(state_key(state),Arc::downgrade(&s));
    let recovery=s.clone();
    tokio::spawn(async move {
        // Registration happens before the LXMF registry. Wait once, then reconstruct from durable spent evidence.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let recovered=Store::new(&recovery.state).and_then(|s|s.recover()).unwrap_or_default();
        for proof in recovered { if proof.rec.node==recovery.identity.public_key_bytes(){ let _=recovery.announce_close(&proof); } }
    });
    let poller=Arc::downgrade(&s);
    tokio::spawn(async move{
        loop{
            tokio::time::sleep(Duration::from_secs(1)).await;
            let Some(s)=poller.upgrade()else{return};
            s.serve_requests().await;
        }
    });
    s
}
#[derive(Deserialize)]
struct IssueReq{root:String,nodes:Vec<String>,cap:u16}
/// Каталог запросов выпуска от CLI другого процесса: `<state>/enroll-req/<32 hex>.req` -> `.out` (приглашение) или `.err`.
pub fn req_dir(state:&Path)->PathBuf{state.join("enroll-req")}
/// Положить запрос демону и дождаться приглашения (для CLI, когда сеть держит другой процесс).
pub fn issue_via_daemon(state:&Path,root:Hash,nodes:&[Hash],cap:u16,wait:Duration)->Result<String>{
    use std::os::unix::fs::PermissionsExt;
    use rand_core::RngCore;
    let dir=req_dir(state);std::fs::create_dir_all(&dir)?;std::fs::set_permissions(&dir,std::fs::Permissions::from_mode(0o700))?;
    let mut raw=[0u8;16];rand_core::OsRng.fill_bytes(&mut raw);let id=hex(&raw);
    let body=serde_json::json!({"root":hex(&root),"nodes":nodes.iter().map(|h|hex(h)).collect::<Vec<_>>(),"cap":cap}).to_string();
    let req=dir.join(format!("{id}.req"));enroll::write(&req,body.as_bytes())?;
    let (out,err)=(dir.join(format!("{id}.out")),dir.join(format!("{id}.err")));
    let start=Instant::now();
    let result=loop{
        if let Ok(v)=std::fs::read_to_string(&out){break Ok(v.trim().to_string())}
        if let Ok(e)=std::fs::read_to_string(&err){break Err(anyhow::anyhow!("{}",e.trim()))}
        if start.elapsed()>wait{let _=std::fs::remove_file(&req);break Err(anyhow::anyhow!("Демон не ответил: запустите узел или VPN и повторите"))}
        std::thread::sleep(Duration::from_millis(300));
    };
    for p in [&req,&out,&err]{let _=std::fs::remove_file(p);}
    result
}
/// Файл каталога запросов старше 10 минут (запрос, ответ с приглашением или временный): подлежит удалению.
fn req_stale(p:&Path)->bool{
    matches!(p.extension().and_then(|e|e.to_str()),Some("out"|"err"|"req"|"tmp"))&&std::fs::metadata(p).and_then(|m|m.modified()).ok().and_then(|t|t.elapsed().ok()).is_some_and(|d|d>Duration::from_secs(600))
}
pub fn session_live(state:&Path,link:&LinkId)->bool{
    find(state).is_some_and(|s|s.sessions.lock().unwrap().get(link).is_some_and(|x|x.until>Instant::now()))
}

/// One msgpack bin value, including exact-length validation. Bodies never exceed 16 KiB.
fn pack(b:&[u8])->Result<Vec<u8>>{if b.len()>enroll::MAX_WIRE{bail!("enrollment message too large")};let mut out=vec![0xc6];out.extend((b.len() as u32).to_be_bytes());out.extend(b);Ok(out)}
fn unpack(b:&[u8])->Result<&[u8]>{if b.len()<5||b[0]!=0xc6{bail!("enrollment msgpack")};let n=u32::from_be_bytes(b[1..5].try_into()?)as usize;if n>enroll::MAX_WIRE||n+5!=b.len(){bail!("enrollment length")};Ok(&b[5..])}
async fn rpc(node:&Node,link:LinkId,body:&[u8],timeout:u64)->Result<serde_json::Value>{
    let bytes=pack(body)?;
    let (_,future)=node.engine().send_request_awaited(&link,PATH,Some(&bytes),Some(timeout)).await.map_err(|e|anyhow::anyhow!("enrollment request: {e:?}"))?;
    let result=tokio::time::timeout(Duration::from_millis(timeout+5000),future).await.context("enrollment timeout")?.map_err(|e|anyhow::anyhow!("enrollment response: {e:?}"))?;
    Ok(serde_json::from_slice(unpack(&result.response_data)?)?)
}
/// Строка в журнал ноды (`log.txt`) без секретов: только тип запроса, статус и время.
fn trace(state:&Path,line:&str){crate::append_log(&state.join("log.txt"),&format!("[{}] {line}",now_ms()))}
pub fn dispatch(state:&Path,link:LinkId,request_id:[u8;16],data:Vec<u8>){
    let Some(s)=find(state)else{return};
    if data.len()>enroll::MAX_WIRE+5{return}
    // Request buffers are bounded before spawning application work. Busy locks never queue unbounded work.
    let body=match unpack(&data){Ok(b)=>b.to_vec(),Err(_)=>return};
    if body.is_empty(){return}
    let service=s.clone();
    let Ok(permit)=s.inflight.clone().try_acquire_owned()else{
        // Пул занят: честный клиент получает ответ сразу, а не ждёт таймаут RPC (R-6).
        tokio::spawn(async move{if let Ok(raw)=pack(br#"{"status":"busy"}"#){let _=service.node.send_response(&link,&request_id,&raw).await;}});return};
    tokio::spawn(async move{
        let _permit=permit;
        // identify клиента мог ещё не дойти до разбора (запрос идёт сразу за ним): короткое ожидание вместо молчаливого отбрасывания,
        // иначе клиент ждёт ответа до таймаута и Link закрывается сторожем неавторизованных.
        let mut peer=None;
        for _ in 0..15{
            peer=service.node.get_remote_identity(&link).map(|i|i.public_key_bytes());
            if peer.is_some(){break}
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let Some(peer)=peer else{trace(&service.state,&format!("зачисление: запрос {} без identify, отброшен",body[0]));return};
        let started=Instant::now();
        let response=service.handle(link,peer,&body).await.unwrap_or_else(|e|{trace(&service.state,&format!("зачисление: запрос {} не выполнен: {e:#}",body[0]));serde_json::json!({"status":"unknown"})});
        if body[0]==3{trace(&service.state,&format!("зачисление: опрос расписок обработан за {} мс, статус {}",started.elapsed().as_millis(),response["status"]))}
        let Ok(raw)=serde_json::to_vec(&response).and_then(|b|pack(&b).map_err(serde::ser::Error::custom))else{return};
        if service.node.send_response(&link,&request_id,&raw).await.is_err(){let _=service.node.send_response_resource(&link,&request_id,&raw).await;}
    });
}

impl Service {
    fn hints(&self)->Vec<serde_json::Value>{
        let Ok(b)=std::fs::read(self.state.join("server.json"))else{return vec![]};
        if b.len()>8192{return vec![]};let Ok(mut v)=serde_json::from_slice::<serde_json::Value>(&b)else{return vec![]};
        v["k"]=serde_json::json!(hex(&self.identity.public_key_bytes()));
        if !v["a"].is_array(){return vec![]};vec![v]
    }
    fn base(&self,proof:&Proof)->Result<Receipt>{
        Ok(Receipt{proof:enroll::hex(&proof.wire()),closed:enroll::hex(&enroll::closed(&self.identity,proof,dest_from_pub_tag(&self.identity.public_key_bytes(),T13_TAG))?),hints:self.hints()})
    }
    fn publish(&self,proof:&Proof)->Result<Receipt>{
        let mut tr=self.trust.lock().unwrap();tr.offer_enrollment(proof.clone())?;tr.save()?;drop(tr);
        let receipt=self.base(proof)?;Store::new(&self.state)?.receipt(&proof.grant.id,receipt.clone())?;Ok(receipt)
    }
    fn send(&self,pk:Pk,op:&str,proof:&Proof,receipt:Option<Receipt>)->bool {
        let exp=proof.grant.expires;
        let env=Envelope{v:4,op:op.into(),sender:hex(&self.identity.public_key_bytes()),exp,body:enroll::hex(&proof.wire()),receipt};
        let Ok(content)=serde_json::to_vec(&env)else{return false};if content.len()>lxmf_admin::MAX_ADMIN_CONTENT{return false}
        let tr=self.trust.clone();let grant=proof.grant.clone();let admin=proof.admin;
        let gate:lxmf_sync::Gate=Arc::new(move||{
            let t=match tr.try_lock(){Ok(t)=>t,Err(std::sync::TryLockError::WouldBlock)=>return None,Err(_)=>return Some(false)};
            Some(grant.fresh(now_ms()as u64/1000)&&grant.verify(&t,&admin).is_ok())
        });
        lxmf_sync::submit(&self.state,lxmf_sync::Command::Send(lxmf_sync::Outbound{title:TITLE.to_vec(),pk,content,gate,exp,ack:false}))
    }
    fn announce_close(&self,p:&Proof)->Result<()> {
        let tr=self.trust.lock().unwrap();let peers=p.grant.nodes.iter().filter(|h|**h!=*self.identity.hash()).filter_map(|h|tr.public_key_in(&p.grant.root,h)).collect::<Vec<_>>();drop(tr);
        for pk in peers{if !self.send(pk,"close",p,None){bail!("LXMF enrollment queue busy")}}Ok(())
    }
    async fn unknown(&self,link:LinkId,peer:Pk)->serde_json::Value{
        let member=self.trust.lock().unwrap().rights(&peer)!=0;
        let delay=self.ban.lock().unwrap().fail(now_ms()as u64,member);
        let permit=self.delays.clone().try_acquire_owned();
        if permit.is_err(){let _=self.node.engine().close_link(&link).await;return serde_json::json!({"status":"unknown"})}
        let _permit=permit.unwrap();
        tokio::time::sleep(Duration::from_millis(delay)).await;
        serde_json::json!({"status":"unknown"})
    }
    async fn handle(self:&Arc<Self>,link:LinkId,peer:Pk,body:&[u8])->Result<serde_json::Value>{
        match body[0] {
            4=>{ // ISSUE: already identified, signed ADD authority, GCM only. No pin on CBC.
                if self.node.engine().link_stats(&link).is_none_or(|s|s.cipher()!=leviculum_std::api::LinkCipher::Gcm){bail!("issue requires GCM")}
                if body.len()<3+148+24{bail!("issue length")};let n=u16::from_le_bytes(body[1..3].try_into()?)as usize;
                if body.len()!=3+n+24{bail!("issue trailing")};let g=Grant::parse(&body[3..3+n])?;let pin=body[3+n..].try_into()?;
                if trust::hash_of(&peer)!=Some(g.issuer){bail!("issue identify")}
                let _io=self.io.lock().unwrap();let tr=self.trust.lock().unwrap();let mut chain=tr.chain_for(&peer);chain.retain(|r|r.root==g.root);
                Store::new(&self.state)?.issue(&tr,&g,&pin,&peer,&chain,now_ms()as u64/1000)?;
                Ok(serde_json::json!({"status":"issued","invite_id":hex(&g.id),"node":hex(self.identity.hash())}))
            }
            1=>{
                if body.len()!=41{bail!("lookup length")};let pin:[u8;24]=body[1..25].try_into()?;
                let mut proof=match Store::new(&self.state)?.lookup(&pin,now_ms()as u64/1000){Ok(p)=>p,Err(_)=>return Ok(self.unknown(link,peer).await)};
                if proof.rec.rights!=0 && proof.rec.holder!=peer{return Ok(self.unknown(link,peer).await)}
                proof.grant.verify(&self.trust.lock().unwrap(),&proof.admin)?;
                let nonce=rand16();let iface=self.node.engine().link_stats(&link).and_then(|s|s.attached_interface()).unwrap_or(usize::MAX);
                {let mut sessions=self.sessions.lock().unwrap();sessions.retain(|_,s|s.until>Instant::now());
                    if sessions.get(&link).is_some_and(|s|s.peer!=peer){bail!("changed identify")}
                    if !sessions.contains_key(&link) && (sessions.len()>=8 || sessions.values().filter(|s|s.iface==iface).count()>=2 || sessions.values().any(|s|s.peer==peer)){bail!("enrollment sessions busy")}
                    sessions.insert(link,Session{peer,nonce,proof:proof.clone(),until:Instant::now()+Duration::from_secs(300),iface});}
                // Повтор после сбоя публикации/потери ответа: запись заново попадает в trust (идемпотентно), иначе pin погашен, а прав нет.
                if proof.rec.rights!=0 {self.publish(&proof)?;return self.nodes_reply(&proof,true)}
                let tr=self.trust.lock().unwrap();
                for r in tr.chain_for(&self.identity.public_key_bytes()).into_iter().filter(|r|r.root==proof.grant.root){if !proof.chain.contains(&r){proof.chain.push(r)}}
                if proof.chain.len()>32{bail!("offer chain quota")}
                // Placeholder record is not evidence; only grant/chain are used before explicit consent.
                Ok(serde_json::json!({"status":"offer","root":hex(&proof.root),"admin":hex(&proof.admin),"grant":hex(&proof.grant.wire()),
                    "chain":proof.chain.iter().map(|r|hex(&r.wire())).collect::<Vec<_>>(),"nonce":hex(&nonce),"client_nonce":hex(&body[25..])}))
            }
            2=>{
                if body.len()!=83{bail!("redeem length")}
                let (template,nonce)={let sessions=self.sessions.lock().unwrap();let s=sessions.get(&link).context("lookup required")?;
                    if s.peer!=peer||s.until<Instant::now(){bail!("expired session")};(s.proof.clone(),s.nonce)};
                if nonce!=body[67..83]{bail!("redeem nonce")}
                let rights=u16::from_le_bytes(body[1..3].try_into()?);let consent=body[3..67].try_into()?;
                let p={let _io=self.io.lock().unwrap();let mut tr=self.trust.lock().unwrap();template.grant.verify(&tr,&template.admin)?;
                    // R-4: место под запись проверяется ДО необратимого claim, иначе pin сгорит без выдачи прав.
                    let store=Store::new(&self.state)?;if store.spent(&template.grant.id)?.is_none()&&!tr.enrollment_room(&template.grant.root){bail!("enrollment record quota")}
                    let mut p=template.clone();p.rec=EnRec::create(&self.identity,&p.grant,peer,rights,consent,now_ms()as u64)?;
                    for r in tr.chain_for(&self.identity.public_key_bytes()).into_iter().filter(|r|r.root==p.grant.root){if !p.chain.contains(&r){p.chain.push(r)}}
                    store.claim(&p)?};
                if p.rec.holder!=peer{return Ok(self.unknown(link,peer).await)}
                self.ban.lock().unwrap().success(); // k сбрасывает только успешная выдача, не LOOKUP (иначе валидный pin обнуляет бан перебора)
                self.publish(&p)?;let response=self.nodes_reply(&p,false)?;
                let _=self.announce_close(&p);Ok(response)
            }
            3=>{
                if body.len()!=17{bail!("nodes length")};let id=body[1..].try_into()?;
                let p=Store::new(&self.state)?.spent(&id)?.context("unknown")?;
                if p.rec.holder!=peer||!p.grant.fresh(now_ms()as u64/1000){return Ok(self.unknown(link,peer).await)}
                self.nodes_reply(&p,true)
            }
            _=>bail!("unknown enrollment request"),
        }
    }
    fn nodes_reply(&self,p:&Proof,repeat:bool)->Result<serde_json::Value>{
        let store=Store::new(&self.state)?;let mut receipts=store.receipts(&p.grant.id)?;
        if !receipts.iter().any(|r|r.proof==enroll::hex(&p.wire())){receipts.push(self.base(p)?)}
        Ok(serde_json::json!({"status":if repeat{"nodes"}else{"result"},"complete":receipts.len()==p.grant.nodes.len(),"receipts":receipts}))
    }

    pub async fn open(&self,h:Hash,issue:bool)->Result<LinkId>{
        let dest=*Destination::compute_destination_hash(&Destination::compute_name_hash("node",&["mesh"]),&h).as_bytes();
        // All peers, including the fresh client, start with a signed announce matching this exact identity hash.
        let dh=DestinationHash::new(dest);let start=Instant::now();let mut asked=Instant::now()-Duration::from_secs(60);
        let pk=loop {
            if let Some(id)=self.node.get_identity(&dh){if *id.hash()==h{break id.public_key_bytes()}}
            if start.elapsed()>Duration::from_secs(40){bail!("Нет подписанного анонса выбранной ноды; проверьте интернет и повторите")}
            if asked.elapsed()>=Duration::from_secs(20){let _=self.node.engine().request_path(&dh).await;asked=Instant::now();}
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        let link=if let Some(ctx)=self.client.as_ref().and_then(Weak::upgrade){
            let known=ctx.servers.lock().unwrap().iter().find(|s|s.dest==dest).cloned();
            let cand=known.unwrap_or(CServer{dest,key:pk[32..].try_into().unwrap(),name:hex(&h)[..8].into(),ep:hex(&pk[32..]),addrs:vec![],hops:None,rtt_ms:None,state:"enroll".into(),seen:Instant::now(),pinned:false,pk:Some(pk)});
            if issue {
                if !cand.addrs.is_empty(){start_dialer(&ctx,&cand);direct_link(&ctx,&cand).await?}
                else{link_via_ours(&ctx,&cand).await.context("Нода недоступна через защищённый носитель")?}
            }else{rns_link(&ctx,&cand).await?}
        }else{
            let cipher=if issue{leviculum_std::api::LinkCipher::Gcm}else{leviculum_std::api::LinkCipher::Cbc};
            let handle=self.node.connect_with_key_cipher(&dh,pk[32..].try_into().unwrap(),cipher).await.map_err(|e|anyhow::anyhow!("enroll connect: {e:?}"))?;
            let link=*handle.link_id();
            tokio::time::timeout(Duration::from_secs(20),self.node.engine().await_link_established(&link)).await.context("enroll Link timeout")?.map_err(|e|anyhow::anyhow!("enroll Link: {e:?}"))?;link
        };
        self.node.identify_link(&link,&self.identity).await.map_err(|e|anyhow::anyhow!("enroll identify: {e:?}"))?;
        Ok(link)
    }
    async fn serve_requests(self:&Arc<Self>){
        let dir=req_dir(&self.state);
        let Ok(rd)=std::fs::read_dir(&dir)else{return};
        let mut served=0;
        for ent in rd.flatten().take(256){
            let p=ent.path();
            // R-7: брошенные ответы (в .out лежит приглашение) и запросы старше 10 минут удаляются; демон берёт только .req.
            if req_stale(&p){let _=std::fs::remove_file(&p);continue}
            let Some(stem)=p.file_stem().and_then(|s|s.to_str()).map(str::to_owned)else{continue};
            if p.extension().and_then(|e|e.to_str())!=Some("req")||stem.len()!=32||!stem.bytes().all(|b|b.is_ascii_hexdigit())||served>=4{continue}
            served+=1;
            let raw=std::fs::read(&p);let _=std::fs::remove_file(&p);
            let res:Result<String>=async{
                let raw=raw?;if raw.len()>4096{bail!("запрос слишком велик")}
                let r:IssueReq=serde_json::from_slice(&raw)?;
                let root:Hash=unhex(&r.root).try_into().map_err(|_|anyhow::anyhow!("root hash"))?;
                if r.nodes.len()>enroll::MAX_NODES{bail!("слишком много нод")}
                let nodes=r.nodes.iter().map(|h|unhex(h).try_into().map_err(|_|anyhow::anyhow!("node identity hash"))).collect::<Result<Vec<Hash>>>()?;
                self.issue_invite(root,nodes,r.cap).await
            }.await;
            let (name,body)=match res{Ok(v)=>("out",v),Err(e)=>("err",format!("{e}"))};
            let _=enroll::write(&dir.join(format!("{stem}.{name}")),body.as_bytes());
        }
    }
    pub async fn issue_invite(self:&Arc<Self>,root:Hash,nodes:Vec<Hash>,cap:u16)->Result<String>{
        let invite=Invite::new(nodes)?;let grant=Grant::create(&self.identity,root,&invite,cap,now_ms()as u64/1000)?;
        grant.verify(&self.trust.lock().unwrap(),&self.identity.public_key_bytes())?;
        let mut accepted=vec![];
        for h in &invite.nodes {
            let result=if *h==*self.identity.hash(){
                let tr=self.trust.lock().unwrap();let mut chain=tr.chain_for(&tr.me_pk);chain.retain(|r|r.root==root);
                Store::new(&self.state)?.issue(&tr,&grant,&invite.pin,&self.identity.public_key_bytes(),&chain,now_ms()as u64/1000).map(|_|())
            }else{async{
                let link=self.open(*h,true).await?;let bytes=grant.wire();let mut body=vec![4];body.extend((bytes.len()as u16).to_le_bytes());body.extend(bytes);body.extend(invite.pin);
                let reply=rpc(&self.node,link,&body,20_000).await;let _=self.node.engine().close_link(&link).await;
                let reply=reply?;if reply["status"]!="issued"||reply["node"]!=hex(h)||reply["invite_id"]!=hex(&grant.id){bail!("issue not acknowledged")};Ok(())
            }.await};
            if result.is_ok(){accepted.push(*h)}
        }
        if accepted.is_empty(){bail!("Ни одна выбранная нода не подтвердила выпуск. Подключите VPN и повторите; приглашение не создано")}
        Invite{nodes:accepted,pin:invite.pin}.encode()
    }
}

#[derive(Serialize,Deserialize)]
struct Envelope{v:u8,op:String,sender:String,exp:u64,body:String,receipt:Option<Receipt>}
pub fn on_lxmf(state:&Path,message:&leviculum_lxmf::Message){
    let Some(s)=find(state)else{return};let _=s.on_lxmf(message);
}
impl Service{
    fn on_lxmf(&self,message:&leviculum_lxmf::Message)->Result<()> {
        if message.title!=TITLE||message.content.len()>lxmf_admin::MAX_ADMIN_CONTENT||message.destination_hash!=lxmf_admin::lxmf_destination(self.identity.hash()){bail!("enroll envelope")}
        let env:Envelope=serde_json::from_slice(&message.content)?;let pk:Pk=enroll::raw(&env.sender)?.try_into().map_err(|_|anyhow::anyhow!("enroll sender"))?;
        if env.v!=4||env.exp<=now_ms()as u64/1000||env.exp>now_ms()as u64/1000+enroll::TTL||!lxmf_admin::signed_by_trusted_source(message,&pk){bail!("enroll source/signature/expiry")}
        let actor=trust::hash_of(&pk).context("sender")?;
        {let mut rate=self.rate.lock().unwrap();let (global,per)=&mut*rate;
            let now=Instant::now();global.retain(|t|t.elapsed()<Duration::from_secs(60));per.retain(|_,v|{v.retain(|t|t.elapsed()<Duration::from_secs(60));!v.is_empty()});
            if global.len()>=60||per.get(&actor).is_some_and(|v|v.len()>=10){bail!("enrollment rate")};global.push_back(now);per.entry(actor).or_default().push_back(now);}
        let p=Proof::parse(&enroll::raw(&env.body)?)?;
        if p.grant.expires!=env.exp{bail!("enroll TTL binding")}
        match env.op.as_str(){
            "close"=>{
                if p.rec.node!=pk{bail!("commissioner identity")};
                let own={let _io=self.io.lock().unwrap();let tr=self.trust.lock().unwrap();Store::new(&self.state)?.close(&tr,&self.identity,&p,now_ms()as u64)?};
                if let Some(own)=own {
                    if own.rec.holder==p.rec.holder {let receipt=self.publish(&own)?;self.send(pk,"closed",&own,Some(receipt));}
                }
            }
            "closed"=>{
                if p.rec.node!=pk{bail!("closing node identity")};let receipt=env.receipt.context("closed receipt")?;
                if receipt.proof!=enroll::hex(&p.wire()){bail!("closed proof mismatch")}
                enroll::verify_closed(&enroll::raw(&receipt.closed)?,&p,dest_from_pub_tag(&pk,T13_TAG))?;
                let _io=self.io.lock().unwrap();let store=Store::new(&self.state)?;let mine=store.spent(&p.grant.id)?.context("unknown commissioner state")?;
                if mine.rec.holder!=p.rec.holder||mine.rec.rights!=p.rec.rights||mine.grant!=p.grant{bail!("closed holder/grant")}
                self.trust.lock().unwrap().offer_enrollment(p.clone())?;self.trust.lock().unwrap().save()?;store.receipt(&p.grant.id,receipt)?;
            }
            "proof"=>{if p.rec.holder!=pk{bail!("proof holder")};self.trust.lock().unwrap().offer_enrollment(p)?;self.trust.lock().unwrap().save()?;}
            _=>bail!("enrollment operation"),
        }
        lxmf_sync::acknowledge(&self.state,message,pk);Ok(())
    }
    pub fn send_proofs(&self,pk:Pk){
        let proofs=self.trust.lock().unwrap().enrollment_proofs(&self.identity.public_key_bytes());
        for p in proofs{if p.rec.scope==trust::hash_of(&pk).unwrap_or([0;16]){self.send(pk,"proof",&p,None);}}
    }
}

/// Новичок отказался в диалоге согласия: повторять приглашение и пробовать другие ноды нельзя.
#[derive(Debug)]
pub struct Declined;
impl std::fmt::Display for Declined{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("Вступление отменено; pin не погашен")}}
impl std::error::Error for Declined{}

/// Нода ответила определённо: приглашение неизвестно, погашено или просрочено. Если так ответили все ноды, повторять бессмысленно
/// (каждая попытка только растит fail2ban нод).
#[derive(Debug)]
pub struct Refused;
impl std::fmt::Display for Refused{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("Приглашение неизвестно, погашено или просрочено. Попросите новое приглашение")}}
impl std::error::Error for Refused{}

/// Newcomer flow, including human consent bound to the signed offer digest and this Link.
pub async fn join(s:&Arc<Service>,invite:&Invite)->Result<Vec<serde_json::Value>>{
    let mut nodes=invite.nodes.clone();let offset=(rand16()[0]as usize)%nodes.len();nodes.rotate_left(offset);
    let mut last=anyhow::anyhow!("Ноды приглашения недоступны");
    let mut refused=0usize;let total=nodes.len();
    for h in nodes {
        match join_one(s,invite,h).await {
            Ok(hints)=>return Ok(hints),
            Err(e)if e.downcast_ref::<Declined>().is_some()=>return Err(e),
            Err(e)if e.downcast_ref::<Refused>().is_some()=>refused+=1,
            Err(e)=>last=e}
    }
    // терминально, когда определённо отказало большинство нод (часть нод может быть недоступна, как fin1 без зачисления);
    // при меньшем числе отказов возвращается ошибка недоступности и клиент повторяет с нарастающей паузой
    if refused*2>total{
        let _=enroll::write(&s.state.join("enrollment.json"),br#"{"v":4,"state":"refused"}"#);
        return Err(anyhow::Error::new(Refused))
    }
    Err(last)
}
async fn join_one(s:&Arc<Service>,invite:&Invite,h:Hash)->Result<Vec<serde_json::Value>>{
    let link=s.open(h,false).await?;
    let result=join_link(s,invite,h,link).await;
    let _=s.node.engine().close_link(&link).await;result
}
async fn join_link(s:&Arc<Service>,invite:&Invite,h:Hash,link:LinkId)->Result<Vec<serde_json::Value>>{
    let client_nonce=rand16();let mut body=vec![1];body.extend(invite.pin);body.extend(client_nonce);
    let offer=rpc(&s.node,link,&body,70_000).await?;
    if offer["status"]=="nodes" {return repeat_nodes(&s.trust,&s.identity,&s.state,invite,h,&offer)}
    if offer["status"]=="busy"{bail!("Нода занята, повторите позже")}
    if offer["status"]!="offer"{return Err(anyhow::Error::new(Refused))}
    let root:Pk=enroll::raw(offer["root"].as_str().context("offer root")?)?.try_into().map_err(|_|anyhow::anyhow!("root"))?;
    let admin:Pk=enroll::raw(offer["admin"].as_str().context("offer admin")?)?.try_into().map_err(|_|anyhow::anyhow!("admin"))?;
    let g=Grant::parse(&enroll::raw(offer["grant"].as_str().context("offer grant")?)?)?;
    if g.id!=enroll::invite_id(&invite.pin)||!g.nodes.contains(&h)||!invite.nodes.iter().all(|n|g.nodes.contains(n))||!g.fresh(now_ms()as u64/1000)||offer["client_nonce"]!=hex(&client_nonce)||trust::hash_of(&root)!=Some(g.root){bail!("Offer не соответствует приглашению")}
    let arr=offer["chain"].as_array().context("offer chain")?;if arr.len()>32{bail!("offer chain quota")}
    let chain=arr.iter().map(|v|trust::Record::parse(&enroll::raw(v.as_str().unwrap_or(""))?).context("offer record")).collect::<Result<Vec<_>>>()?;
    let mut temporary=Trust::new(s.identity.clone(),None);temporary.add_anchor(&root)?;
    for _ in 0..=trust::MAX_DEPTH{for r in &chain{if r.root!=g.root{bail!("foreign offer record")};temporary.offer(r.clone());}}
    g.verify(&temporary,&admin)?;
    let request=hex(&g.digest());let nonce:[u8;16]=enroll::raw(offer["nonce"].as_str().context("offer nonce")?)?.try_into().map_err(|_|anyhow::anyhow!("nonce"))?;
    let confirm=s.state.join("enroll-consent.json");let _=std::fs::remove_file(&confirm);
    let view=serde_json::json!({"v":4,"state":"offer","request":request,"root":hex(&g.root),"issuer":hex(&g.issuer),"rights":g.cap,"expires":g.expires,"nodes":g.nodes.iter().map(|h|hex(h)).collect::<Vec<_>>(),
        // R-2: другие корни, которым это устройство уже доверяет (кроме собственного и предлагаемого): диалог предупреждает о них
        "others":s.trust.lock().unwrap().anchors().into_iter().map(|(h,_)|h).filter(|h|h!=s.identity.hash()&&*h!=g.root).map(|h|hex(&h)).collect::<Vec<_>>()});
    enroll::write(&s.state.join("enrollment.json"),&serde_json::to_vec(&view)?)?;
    let start=Instant::now();let accepted=loop{
        if let Ok(bytes)=std::fs::read(&confirm){if bytes.len()<1024{if let Ok(v)=serde_json::from_slice::<serde_json::Value>(&bytes){if v["request"]==request{break v["accept"].as_bool()==Some(true)}}}}
        if start.elapsed()>Duration::from_secs(290){bail!("Согласие не получено. Подключитесь и повторите приглашение")}
        if s.state.join("fin").exists(){bail!("VPN остановлен")};tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let _=std::fs::remove_file(confirm);
    if !accepted{
        // R-3: приложение по этому состоянию стирает сохранённое приглашение (иначе pin лежал бы в профиле бессрочно)
        let _=enroll::write(&s.state.join("enrollment.json"),br#"{"v":4,"state":"declined"}"#);
        return Err(anyhow::Error::new(Declined))
    }
    enroll::write(&consent_marker(&s.state),&serde_json::to_vec(&serde_json::json!({"id":hex(&g.id),"digest":request}))?)?;
    let consent=EnRec::consent(&s.identity,&g,g.cap)?;let mut redeem=vec![2];redeem.extend(g.cap.to_le_bytes());redeem.extend(consent);redeem.extend(nonce);
    let result=rpc(&s.node,link,&redeem,25_000).await?;
    let mut hints=apply_result(s,invite,h,&result,Some(&request))?;
    let started=Instant::now();let mut complete=result["complete"].as_bool()==Some(true);
    while !complete&&started.elapsed()<Duration::from_secs(30){
        tokio::time::sleep(Duration::from_secs(10)).await;let mut request=vec![3];request.extend(g.id);
        if let Ok(reply)=rpc(&s.node,link,&request,10_000).await {
            hints.extend(apply_result(s,invite,h,&reply,Some(&hex(&g.digest())))?);complete=reply["complete"].as_bool()==Some(true);
        }
    }
    Ok(hints)
}
fn apply_result(s:&Service,invite:&Invite,commissioner:Hash,result:&serde_json::Value,consent:Option<&str>)->Result<Vec<serde_json::Value>>{
    apply_to(&s.trust,&s.identity,&s.state,enroll::invite_id(&invite.pin),commissioner,result,consent,true)
}
/// Дожим расписок после зачисления. Окно `join` (30 с) короче времени, за которое остальные ноды гранта закрывают выдачу по LXMF
/// (при нестабильной mesh это минуты), поэтому телефон мог остаться только с частью нод. Здесь для каждого свежего гранта, по которому
/// записей меньше, чем нод, спрашиваем (`[3]`) ноды, уже подтвердившие права: их ответ несёт все расписки, что у них есть.
/// Якорь не ставится (он уже стоит), согласие - digest сохранённого гранта. `None` - дожимать нечего.
pub async fn refresh(s:&Arc<Service>)->Result<Option<Vec<serde_json::Value>>>{
    let proofs=s.trust.lock().unwrap().enrollment_proofs(&s.identity.public_key_bytes());
    let mut ids:Vec<Hash>=vec![];for p in &proofs{if !ids.contains(&p.grant.id){ids.push(p.grant.id)}}
    let (mut hints,mut worked,mut last)=(vec![],false,None);
    for id in ids{
        let have:Vec<&Proof>=proofs.iter().filter(|p|p.grant.id==id).collect();let grant=&have[0].grant;
        if !grant.fresh(now_ms()as u64/1000)||grant.nodes.iter().all(|n|have.iter().any(|p|p.rec.scope==*n)){continue}
        worked=true;
        for p in &have{
            let h=p.rec.scope;
            let r:Result<Vec<serde_json::Value>>=async{
                let link=s.open(h,false).await?;let mut req=vec![3];req.extend(id);
                // Ответ несёт все расписки ноды (десятки КиБ уходят ресурсом); 10 с ему не хватало (RequestTimedOut на телефоне), как у `join` - 70 с.
                let reply=rpc(&s.node,link,&req,60_000).await;let _=s.node.engine().close_link(&link).await;
                apply_to(&s.trust,&s.identity,&s.state,id,h,&reply?,Some(&hex(&grant.digest())),false)
            }.await;
            match r{Ok(v)=>{hints.extend(v);last=None;break}Err(e)=>last=Some(e)}
        }
    }
    match last{Some(e)=>Err(e),None=>Ok(worked.then_some(hints))}
}
/// Маркер принятого предложения: пишется перед REDEEM (id приглашения и digest grant, без pin) и живёт до применения ответа.
/// Нужен, если ответ на REDEEM потерян после погашения: повтор приглашения тогда приходит как `nodes`, а доказательства ещё нет.
fn consent_marker(state:&Path)->PathBuf{state.join("enroll-consented.json")}
fn consented_digest(state:&Path,id:&Hash)->Option<String>{
    let b=std::fs::read(consent_marker(state)).ok().filter(|b|b.len()<1024)?;let v:serde_json::Value=serde_json::from_slice(&b).ok()?;
    if v["id"]!=hex(id){return None}v["digest"].as_str().map(str::to_owned)
}
/// Ответ `nodes` на первый LOOKUP (R-1): нода считает приглашение уже зачисленным. Без диалога принимается только повтор того,
/// что это устройство уже приняло: сохранённое доказательство с тем же `invite_id` (якорь уже стоит) либо маркер согласия
/// с digest того же grant (ответ на REDEEM потерян). Иначе ничего не ставится, и приглашение идёт через OFFER и диалог.
fn repeat_nodes(trust:&Mutex<Trust>,id:&Identity,state:&Path,invite:&Invite,commissioner:Hash,offer:&serde_json::Value)->Result<Vec<serde_json::Value>>{
    let want=enroll::invite_id(&invite.pin);
    let stored=trust.lock().unwrap().enrollment_proofs(&id.public_key_bytes()).into_iter().find(|p|p.grant.id==want);
    let (digest,anchor)=match stored{
        Some(p)=>(hex(&p.grant.digest()),false),
        None=>(consented_digest(state,&want).context("Нода отвечает, что приглашение уже принято, но на этом устройстве согласия нет; приглашение не применено")?,true),
    };
    apply_to(trust,id,state,want,commissioner,offer,Some(&digest),anchor)
}
#[allow(clippy::too_many_arguments)]
fn apply_to(trust:&Mutex<Trust>,id:&Identity,state:&Path,want:Hash,commissioner:Hash,result:&serde_json::Value,consent:Option<&str>,add_anchor:bool)->Result<Vec<serde_json::Value>>{
    if !matches!(result["status"].as_str(),Some("result"|"nodes")){bail!("Зачисление не подтверждено нодой")}
    let arr=result["receipts"].as_array().context("result receipts")?;if arr.is_empty()||arr.len()>8{bail!("receipt count")}
    let mut parsed=vec![];let mut seen=HashSet::new();let mut hints=vec![];
    for value in arr{
        let r:Receipt=serde_json::from_value(value.clone())?;let p=Proof::parse(&enroll::raw(&r.proof)?)?;
        if p.grant.id!=want||p.rec.holder!=id.public_key_bytes()||!p.grant.nodes.contains(&commissioner)||!seen.insert(p.rec.scope){bail!("result binding/duplicate")}
        if let Some(consent)=consent{if hex(&p.grant.digest())!=consent{bail!("result changed consented offer")}}
        p.authority(id)?;enroll::verify_closed(&enroll::raw(&r.closed)?,&p,dest_from_pub_tag(&p.rec.node,T13_TAG))?;
        if r.hints.len()>8{bail!("hint quota")};hints.extend(r.hints);parsed.push(p);
    }
    if !seen.contains(&commissioner){bail!("commissioner receipt missing")}
    // Persist the trust anchor ONLY after holder-signed consent and independently verified node evidence.
    let mut tr=trust.lock().unwrap();
    for p in parsed {if add_anchor{tr.add_anchor(&p.root)?;}tr.offer_enrollment(p)?;}tr.save()?;drop(tr);
    let _=std::fs::remove_file(consent_marker(state));
    enroll::write(&state.join("enrollment.json"),&serde_json::to_vec(&serde_json::json!({"v":4,"state":"enrolled","complete":result["complete"],"nodes":seen.len()}))?)?;
    Ok(hints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use leviculum_std::api::NodeBuilder;

    async fn pump(state:PathBuf,mut rx:leviculum_std::driver::EventReceiver){
        while let Some(ev)=rx.recv().await {if let NodeEvent::RequestReceived{link_id,request_id,path,data,..}=ev{if path==PATH{dispatch(&state,link_id,request_id,data)}}}
    }
    fn destination(node:&Node,id:&Identity){let mut dest=new_dest(id.clone(),Direction::In,T13_TAG).unwrap();dest.set_accepts_links(true);node.register_destination(dest);}

    /// Ответ ноды `nodes` с корректным доказательством: свой корень, своя нода, подпись согласия новичка (воспроизведена).
    fn replayed_nodes_reply(root:&Identity,node:&Identity,victim:&Identity)->(Invite,serde_json::Value,Proof){
        let mut rtr=Trust::new(root.clone(),None);rtr.issue(*root.hash(),node.public_key_bytes(),trust::USE|trust::TRANSIT|trust::EXIT).unwrap();
        let inv=Invite::new(vec![*node.hash()]).unwrap();let g=Grant::create(root,*root.hash(),&inv,trust::USE,now_ms()as u64/1000).unwrap();
        let consent=EnRec::consent(victim,&g,trust::USE).unwrap();let rec=EnRec::create(node,&g,victim.public_key_bytes(),trust::USE,consent,now_ms()as u64).unwrap();
        let proof=Proof{root:root.public_key_bytes(),admin:root.public_key_bytes(),chain:rtr.chain_for(&node.public_key_bytes()),grant:g,rec};
        let closed=enroll::closed(node,&proof,dest_from_pub_tag(&node.public_key_bytes(),T13_TAG)).unwrap();
        let reply=serde_json::json!({"status":"nodes","complete":true,"receipts":[{"proof":hex(&proof.wire()),"closed":hex(&closed),"hints":[]}]});
        (inv,reply,proof)
    }
    /// R-7: брошенные `.out/.err/.req/.tmp` старше 10 минут удаляются, свежие и посторонние нет.
    #[test]
    fn req_dir_gc_takes_only_stale_request_files(){
        let id=leviculum_std::api::generate_identity();let dir=tmp_state("r7",&id);let old=std::time::SystemTime::now()-Duration::from_secs(700);
        for n in ["a.out","b.err","c.req","d.x.tmp","e.txt","fresh.out"]{std::fs::write(dir.join(n),b"x").unwrap();}
        for n in ["a.out","b.err","c.req","d.x.tmp","e.txt"]{std::fs::File::options().write(true).open(dir.join(n)).unwrap().set_modified(old).unwrap();}
        let stale:Vec<_>=["a.out","b.err","c.req","d.x.tmp","e.txt","fresh.out"].into_iter().filter(|n|req_stale(&dir.join(n))).collect();
        assert_eq!(stale,["a.out","b.err","c.req","d.x.tmp"]);std::fs::remove_dir_all(dir).unwrap();
    }
    fn tmp_state(tag:&str,id:&Identity)->PathBuf{let p=std::env::temp_dir().join(format!("kh-v4-{tag}-{}",hex(id.hash())));std::fs::create_dir_all(&p).unwrap();p}

    /// R-1: чужой корень не получает якорь по `nodes` на первый LOOKUP, пока нет принятого на этом устройстве доказательства.
    #[test]
    fn first_lookup_nodes_reply_does_not_install_foreign_anchor(){
        let(root,node,victim)=(leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity());
        let(inv,reply,_)=replayed_nodes_reply(&root,&node,&victim);
        let state=tmp_state("r1-deny",&victim);let tr=Mutex::new(Trust::new(victim.clone(),Some(state.join("trust.json"))));
        let err=repeat_nodes(&tr,&victim,&state,&inv,*node.hash(),&reply).expect_err("no local consent for this invite");
        assert!(!format!("{err:#}").contains(&hex(&inv.pin)),"pin must not appear in errors");
        let t=tr.lock().unwrap();
        assert!(!t.has_anchor(root.hash()),"foreign root anchor installed without consent dialog");
        assert!(t.enrollment_proofs(&victim.public_key_bytes()).is_empty());
        assert!(!state.join("enrollment.json").exists());drop(t);std::fs::remove_dir_all(state).unwrap();
    }
    /// Ответ на REDEEM потерян после погашения: повтор приходит как `nodes`; маркер согласия того же grant допускает его, чужой digest нет.
    #[test]
    fn first_lookup_nodes_reply_after_lost_redeem_uses_consent_marker(){
        let(root,node,victim)=(leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity());
        let(inv,reply,proof)=replayed_nodes_reply(&root,&node,&victim);
        let state=tmp_state("r1-marker",&victim);let tr=Mutex::new(Trust::new(victim.clone(),Some(state.join("trust.json"))));
        let marker=|digest:String|enroll::write(&consent_marker(&state),&serde_json::to_vec(&serde_json::json!({"id":hex(&proof.grant.id),"digest":digest})).unwrap()).unwrap();
        marker(hex(&[9u8;32]));
        assert!(repeat_nodes(&tr,&victim,&state,&inv,*node.hash(),&reply).is_err(),"marker of another digest");
        assert!(!tr.lock().unwrap().has_anchor(root.hash()));
        marker(hex(&proof.grant.digest()));
        repeat_nodes(&tr,&victim,&state,&inv,*node.hash(),&reply).expect("marker of the same consented grant");
        assert!(tr.lock().unwrap().has_anchor(root.hash()));
        assert!(!consent_marker(&state).exists(),"marker removed after application");
        std::fs::remove_dir_all(state).unwrap();
    }
    /// R-2: «Забыть профиль» удаляет чужие корни и зачисления (и на диске), записи собственного корня остаются.
    #[test]
    fn forget_foreign_roots_keeps_own_root_records_and_drops_enrollments(){
        let(root,node,me,peer)=(leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity());
        let(_,_,proof)=replayed_nodes_reply(&root,&node,&me);
        let state=tmp_state("r2-forget",&me);let mut t=Trust::new(me.clone(),Some(state.join("trust.json")));
        t.issue(*me.hash(),peer.public_key_bytes(),trust::USE).unwrap();
        t.add_anchor(&root.public_key_bytes()).unwrap();t.offer_enrollment(proof).unwrap();t.save().unwrap();
        assert_eq!(t.forget_foreign_roots().unwrap(),1);
        assert!(!t.has_anchor(root.hash())&&t.has_anchor(me.hash()));assert!(t.enrollment_proofs(&me.public_key_bytes()).is_empty());
        let r=Trust::load(me.clone(),&state).unwrap();
        assert!(!r.has_anchor(root.hash()),"anchor stays forgotten after reload");assert!(r.enrollment_proofs(&me.public_key_bytes()).is_empty());
        assert!(r.export_all().iter().any(|x|x.holder==peer.public_key_bytes()),"own-root record survives");
        assert_eq!(r.export_all().iter().filter(|x|x.root!=*me.hash()).count(),0);
        std::fs::remove_dir_all(state).unwrap();
    }
    /// Повтор того, что устройство уже приняло (то же приглашение, тот же grant, якорь на месте), остаётся рабочим.
    #[test]
    fn first_lookup_nodes_reply_accepts_repeat_of_consented_invite(){
        let(root,node,victim)=(leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity());
        let(inv,reply,proof)=replayed_nodes_reply(&root,&node,&victim);
        let state=tmp_state("r1-repeat",&victim);let mut t=Trust::new(victim.clone(),Some(state.join("trust.json")));
        t.add_anchor(&root.public_key_bytes()).unwrap();t.offer_enrollment(proof).unwrap();let tr=Mutex::new(t);
        repeat_nodes(&tr,&victim,&state,&inv,*node.hash(),&reply).expect("consented repeat");
        assert!(tr.lock().unwrap().has_anchor(root.hash()));
        // Ответ с чужим корнем и другим приглашением тем же вызовом не проходит.
        let other=leviculum_std::api::generate_identity();let(_,swapped,_)=replayed_nodes_reply(&other,&node,&victim);
        assert!(repeat_nodes(&tr,&victim,&state,&inv,*node.hash(),&swapped).is_err());
        assert!(!tr.lock().unwrap().has_anchor(other.hash()));
        std::fs::remove_dir_all(state).unwrap();
    }

    #[tokio::test(flavor="multi_thread",worker_threads=4)]
    async fn remote_v4_issue_admin_offline_then_consent_and_scoped_access(){
        let(root,exit,client)=(leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity(),leviculum_std::api::generate_identity());
        let base=std::env::temp_dir().join(format!("kh-v4-network-{}",hex(root.hash())));std::fs::create_dir_all(&base).unwrap();
        for name in ["root","exit","client"]{std::fs::create_dir_all(base.join(name)).unwrap();}
        let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let addr=listener.local_addr().unwrap();drop(listener);
        let mut root_tr=Trust::new(root.clone(),Some(base.join("root/trust.json")));
        let r=root_tr.issue(*root.hash(),exit.public_key_bytes(),trust::USE|trust::TRANSIT|trust::EXIT).unwrap();root_tr.save().unwrap();
        let mut exit_tr=Trust::new(exit.clone(),Some(base.join("exit/trust.json")));exit_tr.add_anchor(&root.public_key_bytes()).unwrap();assert_eq!(exit_tr.offer(r),trust::Offer::Added);exit_tr.save().unwrap();
        let(processor,rt)=lxmf_admin::AdminProcessor::new(exit.clone());
        let pn=lxmf_sync::propagation_processor(&base.join("exit"),exit.clone()).unwrap();
        let mut e=NodeBuilder::new().identity(exit.clone()).storage_path(base.join("exit/transport")).enable_transport(true).add_tcp_server(addr)
            .accept_cbc_links(true).link_cipher(leviculum_std::api::LinkCipher::Gcm).core_processor(lxmf_sync::Processors(processor,pn)).build().unwrap();e.start().await.unwrap();
        let erx=e.take_event_receiver().unwrap();let mut e=Arc::new(e);destination(&e,&exit);
        let service=register(e.clone(),exit.clone(),Arc::new(Mutex::new(exit_tr)),&base.join("exit"),None);
        let _sync=lxmf_sync::register(&base.join("exit"),rt.sync.clone());
        tokio::spawn(pump(base.join("exit"),erx));
        let mut a=NodeBuilder::new().identity(root.clone()).storage_path(base.join("root/transport")).add_tcp_client(addr).accept_cbc_links(true).build().unwrap();a.start().await.unwrap();
        let arx=a.take_event_receiver().unwrap();let mut a=Arc::new(a);destination(&a,&root);
        let admin=register(a.clone(),root.clone(),Arc::new(Mutex::new(root_tr)),&base.join("root"),None);
        tokio::spawn(pump(base.join("root"),arx));
        tokio::time::sleep(Duration::from_millis(300)).await;
        e.announce(&DestinationHash::new(dest_from_pub_tag(&exit.public_key_bytes(),T13_TAG)),None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let code=admin.issue_invite(*root.hash(),vec![*exit.hash()],trust::USE).await.expect("remote durable ISSUE ACK");
        let inv=Invite::parse(&code).unwrap();assert_eq!(inv.nodes,vec![*exit.hash()]);
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(admin);
        Arc::get_mut(&mut a).unwrap().stop().await.unwrap(); // the administrator is NOT online for redemption
        let mut c=NodeBuilder::new().identity(client.clone()).storage_path(base.join("client/transport")).add_tcp_client(addr).accept_cbc_links(true).build().unwrap();c.start().await.unwrap();
        let crx=c.take_event_receiver().unwrap();let mut c=Arc::new(c);destination(&c,&client);
        let receiver=register(c.clone(),client.clone(),Arc::new(Mutex::new(Trust::new(client.clone(),Some(base.join("client/trust.json"))))),&base.join("client"),None);
        tokio::spawn(pump(base.join("client"),crx));
        tokio::time::sleep(Duration::from_millis(300)).await;
        e.announce(&DestinationHash::new(dest_from_pub_tag(&exit.public_key_bytes(),T13_TAG)),None).await.unwrap();
        let dir=base.join("client");
        let root_hash=*root.hash();
        let consent=tokio::spawn(async move{
            let start=Instant::now();loop{
                if let Ok(bytes)=std::fs::read(dir.join("enrollment.json")){if let Ok(v)=serde_json::from_slice::<serde_json::Value>(&bytes){if v["state"]=="offer"{
                    assert_eq!(v["rights"],trust::USE);assert_eq!(v["issuer"],hex(&root_hash));
                    enroll::write(&dir.join("enroll-consent.json"),serde_json::to_string(&serde_json::json!({"request":v["request"],"accept":true})).unwrap().as_bytes()).unwrap();break
                }}}
                assert!(start.elapsed()<Duration::from_secs(35),"signed OFFER missing");tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        tokio::time::timeout(Duration::from_secs(45),join(&receiver,&inv)).await.unwrap().expect("consented v4 enrollment");consent.await.unwrap();
        assert!(receiver.trust.lock().unwrap().common_with(&exit.public_key_bytes(),trust::USE,trust::EXIT,false,true,now_ms()as u64));
        assert!(service.trust.lock().unwrap().common_with(&client.public_key_bytes(),trust::EXIT,trust::USE,true,false,now_ms()as u64));
        assert_eq!(receiver.trust.lock().unwrap().rights_in(root.hash(),client.hash()),0,"no ALL grant from invitation");
        assert!(refresh(&receiver).await.expect("refresh with every receipt present").is_none(),"one-node grant is complete: nothing to refresh");
        let restored=Trust::load(client.clone(),&base.join("client")).unwrap();assert!(restored.common_with(&exit.public_key_bytes(),trust::USE,trust::EXIT,false,true,now_ms()as u64));
        drop(receiver);drop(service);tokio::time::sleep(Duration::from_secs(2)).await;
        Arc::get_mut(&mut c).unwrap().stop().await.unwrap();Arc::get_mut(&mut e).unwrap().stop().await.unwrap();std::fs::remove_dir_all(base).unwrap();
    }
}
