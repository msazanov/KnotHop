"""Интероп хаба RRC с клиентом rrc-tui (его client.py, Python RNS) - ТОЛЬКО локальная лаборатория, не публичная RNS.
Хаб: `KH_RRC_PORT=47553 KH_RRC_OUT=hub.hash cargo test --lib rrc_interop_server -- --ignored --nocapture`; клиенты:
`RRC_TUI_PATH=<клон rrc-tui> python rrc_interop_probe.py b 47553 $(cat hub.hash) /tmp/cfg_b` и то же с ролью `a`.
Конфиг RNS изолированный (TCP на 127.0.0.1, без AutoInterface). Для rrcd задавайте абсолютный configdir в rrcd.toml,
иначе он берёт ~/.reticulum с AutoInterface."""
import sys, os, time, json, logging
sys.path.insert(0, os.environ.get("RRC_TUI_PATH", "rrc-tui"))
import RNS
from rrc_tui.client import Client, ClientConfig

role, port, hubhex, workdir = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
os.makedirs(workdir, exist_ok=True)
open(os.path.join(workdir, "config"), "w").write(f"""[reticulum]
  enable_transport = No
  share_instance = No
  instance_name = rrcprobe{role}
[logging]
  loglevel = 3
[interfaces]
  [[Lab]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {port}
""")
RNS.Reticulum(configdir=workdir, loglevel=RNS.LOG_ERROR)
ident = RNS.Identity()
ev = []
def log(kind, **kw):
    print(json.dumps({"t": round(time.time() % 1000, 2), "who": role, "ev": kind, **kw}, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)), flush=True)

c = Client(ident, ClientConfig(), nickname=f"nick{role}")
c.on_welcome = lambda e: log("welcome", body=e.get(6))
c.on_joined = lambda r, e: log("joined", room=r, body=e.get(6))
c.on_parted = lambda r, e: log("parted", room=r, body=e.get(6))
c.on_message = lambda e: log("msg", room=e.get(5), body=e.get(6), nick=e.get(7), src=e.get(4))
c.on_notice = lambda e: log("notice", body=e.get(6))
c.on_error = lambda e: log("error", body=e.get(6), room=e.get(5))
c.on_close = lambda: log("closed")
c.on_pong = lambda e: log("pong", body=e.get(6))
hub = bytes.fromhex(hubhex)
t0 = time.time()
c.connect(hub, timeout_s=40)
log("connected", secs=round(time.time() - t0, 1), limits=[c.max_nick_bytes, c.max_room_name_bytes, c.max_msg_body_bytes, c.max_rooms_per_session, c.rate_limit_msgs_per_minute])
c.start_ping_thread(interval=5.0)
c.join("Lobby")
time.sleep(float(os.environ.get("JOIN_WAIT", "6")))
if role == "a":
    for i in range(3):
        c.msg("lobby", f"привет {i} from a"); time.sleep(0.5)
    c.msg("lobby", "x" * 350)
    try: c.msg("lobby", "y" * 400)
    except ValueError as e: log("client_refused_long", err=str(e))
time.sleep(float(os.environ.get("RUN_SECS", "20")))
c.part("lobby")
time.sleep(2)
log("rooms_after_part", rooms=sorted(c.rooms), link_active=bool(c.link and c.link.status == RNS.Link.ACTIVE))
c.close()
