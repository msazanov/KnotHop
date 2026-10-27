# IPv6 внутри протокола и адрес клиента из identity: оценка осуществимости

Дата: 27.10.2026. Только чтение кода и открытых источников; ничего не собиралось и не раскатывалось. Пометка «не подтверждено» означает, что факт не проверен по источнику или на устройстве.

## Проблема и главный вывод

Сейчас `client_ip` (`vpn.rs:621`) берёт 17 бит хеша identity; перебор занимает секунды. Адрес жертвы можно занять первым, и тогда `AddressInUse` (`lib.rs:1889`) блокирует настоящего владельца.

**Адрес из 64 бит identity не убирает потребность в динамическом IPv4 на выходе.** Любая схема «IPv6 внутри» для IPv4-интернета упирается в 32 бита: ULA /64 не отображается алгоритмически в пул IPv4 ([RFC 7915](https://www.rfc-editor.org/rfc/rfc7915.html) §6 допускает только RFC 6052 или явную таблицу, [RFC 7757](https://www.rfc-editor.org/rfc/rfc7757) EAM). Выходу всё равно нужна таблица «Link ↔ IPv4 из пула», то есть вариант C. А безопасность решает сам отказ от выведения адреса из хеша, а не размер адреса.

## 1. Android VpnService (API 29–36)

Проверено по исходникам AOSP, ветки `main` и `android16-release`. Построчной проверки для каждого API нет.

- **CLAT на VPN-интерфейсе не запускается.** `Nat464Xlat.requiresClat` требует `TYPE_MOBILE`, `TYPE_WIFI` или `TYPE_ETHERNET` (или test-сеть) и сеть без IPv4 ([Nat464Xlat.java](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/main/service/src/com/android/server/connectivity/Nat464Xlat.java), строки 68–74, 135–157). `Vpn.java` создаёт агент с `setLegacyType(TYPE_VPN)` (строка 1598), поэтому NAT64-префикс на VPN не определяется и `v4-tunX` не появляется. Следствие по коду: `LinkProperties.getNat64Prefix()` для VPN `null`; прямой проверки на устройстве не было.
- **IPv4 при IPv6-only TUN блокируется.** В `makeLinkProperties` ([Vpn.java](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/services/core/java/com/android/server/connectivity/Vpn.java), строки 1474–1523) при отсутствии IPv4-адреса, IPv4-маршрута и IPv4 DNS в сеть VPN добавляется `0.0.0.0/0 RTN_UNREACHABLE`. IPv4-литералы и приложения с AF_INET-сокетами получают `ENETUNREACH`.
- **`allowFamily(AF_INET)` не решает задачу.** Документация даёт одну строку: «Allows traffic from the specified address family» ([Builder](https://developer.android.com/reference/android/net/VpnService.Builder)). По коду выше семейство считается разрешённым, unreachable-маршрут не ставится, а маршрута в TUN нет, значит трафик пойдёт мимо VPN, то есть утечка реального IP. Это вывод из кода, на устройстве не проверялся.
- **IPv4-приложениям нужен IPv4 в TUN.** Это значит `addAddress(ipv4,…)` и `addRoute("0.0.0.0",0)`. Приложения кладут IPv4-пакеты в TUN, и трансляцию в `64:ff9b::/96` приходится делать самим, то есть CLAT внутри `knothopd`/JNI. DNS64 тогда не нужен: приложения резолвят A-записи. Маршрут `64:ff9b::/96` для чистого IPv6-TUN можно добавить через `addRoute`, но IPv4-литералы он не спасёт.
- **Уже сейчас** `KnotHopVpnService.java:231–234` ставит и IPv4-адрес с маршрутом `0.0.0.0/0`, и `fd99:99::2/128` с `::/0`. IPv6 попадает в TUN и отбрасывается (`not_ipv4`). Двухсемейный TUN готов.
- **Известные VPN.** Tailscale (100.64/10 плюс ULA fd7a:115c:a1e0::/48) и WireGuard с IPv6-only `Address` на Android: поведение IPv4 у них по документации не проверялось. Данных, что какой-то массовый Android-VPN даёт рабочий IPv4 поверх IPv6-only TUN, не найдено: «не подтверждено». MTU IPv6 на интерфейсе должен быть не меньше 1280; у нас 1327.
- **Выбор адреса.** Приложения при ULA-only IPv6 и IPv4 в TUN вероятно выберут IPv4 по RFC 6724 (политика ULA/label): не подтверждено, проверять на устройстве.

## 2. NAT64 на Linux-ноде

- **nftables NAT64 не умеет.** В `nft(8)` нет упоминаний NAT64/NAT46. Wiki описывает только NAT в семействе `inet`, где ip и ip6 обрабатываются раздельно ([wiki](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT))). Слияние Jool в nftables остаётся открытым ([Jool #273](https://github.com/NICMx/Jool/issues/273)); у Jool режимы Netfilter и iptables ([intro](https://www.jool.mx/en/intro-jool.html)).
- **Jool** (модуль ядра) и **Tayga** (userspace через TUN, stateless, статическая карта) требуют новой службы или модуля, то есть отдельного разрешения. eBPF `bpf_skb_change_proto` предназначен для NAT64 ([bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)), но нужны CAP_BPF/NET_ADMIN и tc: новые привилегии.
- **SIIT в userspace `knothopd` возможен.** Мы уже читаем/пишем пакеты TUN, а `tun_reader` и `on_link_packet` (`lib.rs:2157, 2270`) единственные точки входа. Схема: Link IPv6 → SIIT (src ULA → IPv4 из таблицы EAM, dst `64:ff9b::a.b.c.d` → a.b.c.d) → khd0 → kernel masquerade → ответ в обратную сторону. Сложность по RFC 7915:
  - заголовки: TTL↔hop limit, TOS↔traffic class, DF/ID↔Fragment Header, длины; IPv4-опции отбрасываются;
  - у ICMPv6 в контрольной сумме псевдозаголовок, у ICMPv4 нет: пересчёт на каждом ICMP;
  - UDP с нулевой checksum из IPv4 в IPv6 нужна полная пересумма; фрагментированный такой UDP по умолчанию отбрасывается;
  - таблица соответствий типов/кодов ICMP, ICMP-ошибки с вложенным заголовком (рекурсия на один уровень, MTU в Packet Too Big корректируется на 20 Б);
  - IPv6 Fragment Header и неподдерживаемые extension headers, генерация ICMP-ошибок самим транслятором;
  - `64:ff9b::/96` нельзя использовать для частных IPv4 ([RFC 6052](https://www.rfc-editor.org/rfc/rfc6052) §3.1): совпадает с нашим `classify_destination`, но правило надо дублировать для embedded-адреса.
  - Оценка объёма: ~1000–1500 строк Rust плюс fuzz/differential-тесты против Tayga/Jool (оценка, не замер).
- **Overhead (оценка).** +20 Б заголовка на каждый пакет по Link. TCP ACK 40→60 Б (+50%), полноразмерный пакет +1,5%. Лимит Link MDU 1327, значит IPv4-MTU на khd0 нужен 1307, MSS падает с 1287 до 1267. CPU трансляции вероятно ~0,1–0,3 мкс на пакет, малая доля по сравнению с GCM, но замера нет. По правилам проекта до внедрения нужно измерение PPS/CPU.

## 3. Альтернатива без IPv6 (вариант C)

Клиент всегда использует один и тот же локальный TUN-адрес, например `10.99.0.2/32` (как сейчас служебная сеть `10.99.0.0/24`). Выход при допуске выбирает свободный адрес из пула и хранит привязку `identity → IPv4` на диске (это и есть «постоянная привязка» из ближайшего плана, но адрес **выдаётся**, а не выводится из хеша). Затем:

- ingress с Link: `src local → pool[link]`; egress в Link: `dst pool[link] → local`;
- сдвиг применяется к 2 полям: инкрементальные checksum IP-заголовка и TCP/UDP ([RFC 1624](https://www.rfc-editor.org/rfc/rfc1624)); для UDP с нулевой checksum она остаётся нулевой;
- ICMP-ошибки: переписать внутренний IP-заголовок и его checksum; у внутреннего TCP/UDP checksum может быть обрезана (8 Б) и не пересчитывается. Echo и прочие ICMPv4 псевдозаголовка не имеют;
- фрагменты: поправка checksum только в первом фрагменте (поле транспортной checksum находится в нём, дельта от адресов не зависит от данных); остальные требуют лишь checksum IP-заголовка;
- ESP/GRE/SCTP: только IP-заголовок. IPv4-опции с адресами (RR/TS) игнорируются.

Размер пакета не меняется, wire-overhead нулевой, пул и хеш-таблицы `routes`/`allowed` уже есть. Оценка: 200–400 строк плюс тесты (checksum-эквивалентность с полной пересуммой, fuzz). Адрес клиента при смене выхода остаётся неизменным (в TUN всегда один). Сброс TUN не нужен, потому что клиент не знает пул. Проверки `allowed[link]==src` (`lib.rs:2171`) и nft-наборы `host_access_v4` продолжают работать на pool-адресах: переписывание идёт до `write_tun`.

## 4. Объём переделки под IPv6 внутри

(по `grep`, число мест приблизительное)

| Область | Файлы и места |
|---|---|
| Ядро пакетов | `lib.rs`: `valid_ipv4_packet` 1854 (+3 вызова: 2159/2214/2294); смещения 12..20 в 2171/2187/2202/2304/2309/2362/2365/2395/2403; `host_service_packet_valid` 2376 (IHL=5); `is_icmp_echo_*` 2391; `icmp_echo` проба 2411; `tun_supervisor` parse 2451; ключи `routes`/`allowed` типа `u32` 1811/1814/1931; ~46 упоминаний u32 |
| Host ACL | `host_acl.rs`: `Inventory` на `HashSet<u32>`, `interface_ipv4` (getifaddrs AF_INET) 103, пул `(u32,u8)` и `validate_pool` 8..=24, nft-наборы `ipv4_addr` 347; 25 u32-мест; `HostAccessRecord` в `trust.rs:178` и конфиг в `vpn.rs` («exact IPv4») |
| Маршрутизация | `route.rs`: диапазоны `(u32,u32)`, `load_cidrs` 166 (IPv6 geoip сейчас отбрасывается), DNS-snoop только A (typ==1, 598; нужно AAAA), `blocks_encrypted_dns` 545, `parse_cidr` 663, `cap_cidrs` 706, формат `direct.cidr`; 51 u32-место |
| Адресация | `vpn.rs`: `client_ip`/`client_net`/`parse_net`/`net_str` 593–636, `--client-net` 153, `whoami.json` 6680, TUN-параметры 3459 и 7359–7371 |
| Android Java | `KnotHopVpnService.java` 123 (tunIp), 231–234 (Builder), 296 (excludeRoute принимает IPv6), 310 (regex IPv4 для `direct.cidr`); `RoutingCfg.java` 290–297 (валидация IPv4); `TopologyView.java` 154; JNI-крейт (107 строк) почти без IPv4 |
| Узлы (nft и скрипты) | `deploy-0013/knothop.nft`: наборы `*_v4`, internal-drop списки, `table ip knothop_nat`, loop-guard, `client-ipv6` drop (понадобятся зеркальные ip6-цепочки и NAT66 или SIIT); `node-hostfix.sh` (ip_forward, `ip6` forward), `node-migrate.sh`, `push.py` (метки nft) |
| Тесты | `deploy/test_nft_isolation.py`, `test_host_acl.py`, `test_push.py`, `bench/tests/lxmf_host_*`, `bench/android/lab13.py`, `bench/l3_cell.py` |

## 5. Рекомендация

| Вариант | Суть | Риски |
|---|---|---|
| **A. IPv6-only + SIIT** | IPv4-приложениям нужен IPv4 в TUN, значит всё равно двухсемейный TUN, CLAT на клиенте и NAT64 на выходе плюс EAM-таблица (то есть C внутри A) | Максимальный объём (§4 целиком + транслятор), +20 Б/пакет, ICMP/фрагменты/PMTU, новые ACL-пути для embedded IPv4, DNS64 если IPv6-only без CLAT. Не решает ничего, чего не решает C |
| **B. Dual-stack** | IPv4 как в C плюс ULA из identity для IPv6, на выходе NAT66 (`ip6 masquerade`) | Копия изоляции для IPv6 (internal drop, host ACL v6, loop-guard), нужен IPv6 на каждом узле (на части не подтверждён). Даёт IPv6-назначения и снимает «чёрную дыру» IPv6. Стоит делать после C отдельной волной, с проверкой на устройстве |
| **C. IPv4 + привязка + динамический IPv4 на выходе** | см. §3 | Наименьший: ~300 строк, ноль overhead по размеру. Риски: ICMP-ошибки с вложенным заголовком и фрагменты (покрыть тестами), IPv4-опции с адресами, исчерпание пула (сейчас ≤256 клиентов на выход) |

**Рекомендую C сейчас.** Привязку делать выдачей, а не выведением из хеша: иначе гонка за «чужим» адресом остаётся. B можно добавить позже без перестройки C, потому что IPv6-адрес по-прежнему можно вывести из identity (64 бита для ULA `fdxx:…`, подбор ~2^64): атака захвата тогда нереалистична, но таблица Link↔IPv4 остаётся для IPv4. A не рекомендую: цена максимальная, выигрыша перед C нет.

## 6. Что проверить на устройстве до решения

1. IPv6-only TUN на HONOR (Android 16) и втором телефоне другой версии: `ping 1.1.1.1`, Chrome на `http://1.1.1.1`, `ip route get 1.1.1.1` и `dumpsys connectivity` (ожидается `ENETUNREACH`/unreachable и отсутствие `v4-tun0`; `ip link`).
2. `allowFamily(AF_INET)` на IPv6-only TUN: не уходит ли IPv4 мимо туннеля (внешний IP сайта-эхо).
3. Двухсемейный TUN с ULA-only IPv6: на что идут Chrome/curl при имени с A и AAAA (RFC 6724), не зависают ли IPv6-попытки без глобального IPv6.
4. Приложения с зашитыми IPv4 (мессенджеры, игры, WebRTC/STUN): как работают в варианте C (должны работать как сейчас).
5. Для C: нагрузочный замер PPS/CPU выхода с переписыванием (должен быть в пределах шума), ICMP-ошибки (PMTU, traceroute) и фрагментированный UDP через туннель.
