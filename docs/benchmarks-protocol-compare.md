# Исторические измерения (не текущая спецификация): knothop/RNS–iroh, Xray и AmneziaWG 3.1

> **Устарело.** Здесь клиенту давались 2 ядра, а генератор шаблона считал каждый байт отдельно
> (на быстрых стеках это само занимало заметную часть ядра). Актуальное сравнение на
> **1 ядре на каждый узел**, с памятью и задержкой в простое — [benchmarks-1core.md](benchmarks-1core.md).


Локальный стенд, общий i7-8750H, Docker internal, никакого публичного RNS-трафика.
На каждом сервере — один logical CPU affinity slot, клиенту два; C=4–5, E=3,
A=6 для двух звеньев. Проверена effective affinity. Это не Android и не Internet.

## Реализации и методика

- **KnotHop**: текущий локальный форк leviculum, GCM v1, записи 64000, HW_MTU 65536,
  send window 4, window-only (QUIC pacing сохранён). VPN payload остаётся в RNS.
- **Чистый iroh 1.3.0/QUIC**, без RNS, HDLC и внутреннего GCM: тот же workload
  `tcp-load`, Endpoint Minimal, relay disabled, собственное QUIC packet protection
  с ключами TLS 1.3. Bulk и echo — отдельные bidi streams одного соединения.
  Для C→A→E A копирует streams между двумя QUIC-соединениями. Это отдельный
  comparator, не продуктовый обход RNS. Пять прогонов добавлены отдельной серией.
- **Xray 26.7.28**, image digest
  `ghcr.io/xtls/xray-core@sha256:b697cda1588faca696ab7f7755dd1161f60862af3ff6026300e44cff6aedd558`:
  VLESS + REALITY + Vision, TCP, mux выключен. REALITY target — локальный
  OpenSSL TLS 1.3/X25519 fixture, не внешний сайт. Частный адрес тестового сервера
  разрешён отдельным freedom finalRule (в этой версии private targets блокируются
  по умолчанию). Настройки исходного/production Xray не читались и не менялись.
- **AWG**: userspace `amneziawg-go v3.1.20260828`, tools `v3.1.20260812`, те же
  проверенные бинарники, что в [AWG.md](../bench/AWG.md). MTU 1280, header
  protection включён, Jc=5, S1/S2/S3/S4=40/60/30/15, random trailers **off**,
  padding 0-0. Это не kernel AWG и не полный padding/trailers профиль.
- Xray и AWG — отдельные неизменённые процессы, они не включены в продуктовый
  стек KnotHop. Xray LICENSE v26.7.28 — MPL-2.0; AWG-go MIT, tools GPLv2,
  см. первоисточники в конце. Решение D4 не меняется.

`tcp-load` (Rust) создаёт полезный TCP-поток для Xray/AWG и отдельное постоянное
echo-соединение. Используется тот же offset-dependent pattern, что в KnotHop,
пошаблонная сверка каждого байта обязательна. SHA включён только в integrity-ячейках.
Запись TCP-компаратора имеет 4-байтный длиновой header; RNS использует свой envelope.
Echo — 16 байт, не чаще одного на 100 мс после ответа, timeout 2 с.

Пять прогонов по 10 с на протокол/топологию. Основная серия knothop/Xray/AWG шла
последовательными тройками. Обнаружена разница прогрева echo: RNS открывал второй
Link после go, TCP-компараторы — до go. Исправлено в стенде, затем KnotHop повторён
отдельной серией `compare-rawg-warm-*`. Старые `compare-rawg-{direct,chain}-*`
сохранены. Высокий p99 RNS после прогрева остался, только startup его не объясняет.
Хост общий, серии после фикса не interleaved; небольшой разрыв RTT нельзя считать
доказанным преимуществом протокола. Разрыв скорости многократный и виден во всех
прогонах. p99 коротких серий чувствителен к единичным outliers.

Две топологии:

1. **C → E**: direct iroh/QUIC под RNS; VLESS/REALITY до E; прямой AWG tunnel C–E.
2. **C → A → E**: RNS forwarding; цепочка двух Xray VLESS/REALITY соединений;
   AWG C–A и A–E с IP forwarding в namespace A. Это разные модели защиты:
   RNS сохраняет сквозную AEAD C–E; Xray/AWG здесь заканчивают транспортную
   защиту на A, который видит синтетический plaintext. С TLS приложения A видел
   бы TLS-ciphertext. **Vision TLS passthrough fast path здесь не тестируется**:
   payload синтетический, без прикладного TLS.

В encrypted-компараторах C запрещён прямой TCP к outer E:4241/4242, AWG server
слушает только туннельный IP. Route/handshake AWG проверены. Ключи/UUID создаются
случайно, configs 0600 только в контейнерных /run, не CLI/отчёт/repo.

## Одно звено, медианы пяти прогонов

| Стек | МиБ/с | CPU s/GiB клиента | CPU s/GiB сервера | echo p95, мс | p99, мс |
|---|---:|---:|---:|---:|---:|
| knothop/RNS–iroh GCM | 46,59 | 11,21 | 20,94 | 8,95 | 67,13 |
| Чистый iroh/QUIC, без RNS | 254,59 | 4,41 | 3,74 | 5,85 | 9,59 |
| Xray VLESS–REALITY–Vision | 351,40 | 2,29 | 2,71 | 5,23 | 8,54 |
| AWG 3.1 userspace | 192,18 | 4,57 | 5,03 | 24,59 | 32,70 |

Xray примерно ×7,5 быстрее KnotHop и требует около ×4,9 меньше CPU клиента на объём;
AWG примерно ×4,1 быстрее, CPU клиента около ×2,5 меньше. Это результат данных
конфигураций, не утверждение для любых устройств/сетей/режимов Xray/AWG.

## Два звена, медианы пяти прогонов

| Стек | МиБ/с | CPU s/GiB клиента | выхода E | релея A | echo p95, мс | p99, мс |
|---|---:|---:|---:|---:|---:|---:|
| knothop/RNS–iroh GCM | 42,37 | 11,11 | 20,38 | 15,85 | 9,81 | 47,27 |
| Чистый iroh/QUIC chain | 201,75 | 4,40 | 4,11 | 4,64 | 21,81 | 38,35 |
| Xray chain | 330,88 | 2,49 | 2,89 | 1,56 | 8,62 | 13,19 |
| AWG chain | 122,50 | 5,32 | 6,04 | 7,34 | 42,94 | 53,67 |

RNS требует около ×10 CPU/GiB на релейном A против Xray chain и ×2,2 против AWG
chain. Модель защиты и задачи различаются: RNS transport дополнительно обрабатывает
RNS framing/routing/dedup, endpoints подтверждают Channel доставку и сквозную AEAD.
Сколько стоит каждый компонент отдельно, этой серией не измерено.

Таймаутов echo в основных сериях нет. Ни отдельный RNS Link, ни отдельное TCP
соединение не гарантируют отсутствие очередей; все делят CPU и нижний путь.

## Overhead и CPU: границы сравнения

Наблюдаемый TX eth0/payload: KnotHop 1,035, Xray 1,004, AWG 1,083 на обоих
топологиях. **Это не wire-проценты**: TSO/GSO/GRO включены, и TCP/UDP offload
по-разному отражаются в счётчиках veth. Wire ranking по этим числам делать нельзя.
Для двух звеньев учтено только первое звено клиента, не сумма C–A и A–E.

CPU — cgroup usage, все процессы роли (включая payload generator/checker,
crypto daemon, локальный TLS fixture). Host softirq может учитываться вне cgroup,
особенно заметно это для туннельного IP forwarding. Поэтому это proxy для
процессорной работы, не полная стоимость ядра/устройства и не батарея Android.

TCP-компараторы используют TCP flow control и default buffers, RNS — своё окно
256 КиБ. TCP echo имеет отдельное TCP transport connection, RNS echo делит iroh
stream с bulk. Результат относится к реализованным профилям, а не чистым cipher
примитивам или одинаковому byte-window на всех нижних слоях.

Контроль plain TCP без криптографии: smoke 570 МиБ/с, checker не ограничивает KnotHop
до 40–50 МиБ/с. Это не отдельная пятипрогонная baseline-серия.
Снятие cap KnotHop до 32 records не помогло: три прогона, медиана 45,49 МиБ/с,
p95 62,89 мс (`compare-rawg-peak-*`). Больше backlog — не решение разрыва скорости.

## Ровно 2 ГиБ, SHA на обоих концах

| Стек | C → E, МиБ/с | C → A → E, МиБ/с |
|---|---:|---:|
| KnotHop | 35,86 | 34,67 (предыдущая integrity-серия 0010) |
| Чистый iroh/QUIC | 99,36 | 100,64 |
| Xray | 110,99 | 105,76 |
| AWG 3.1 userspace | 97,39 | 73,05 |

Размеры совпали, пошаблонная сверка и SHA-256 совпали везде. Скорость падает из-за
SHA на единственном CPU сервера; эти integrity-ячейки не заменяют speed-серию.
KnotHop direct integrity-ячейка предшествует унификации echo warmup.

## Вывод для проекта

Чистый iroh direct примерно ×5,5 быстрее KnotHop, через A — ×4,8. Значительная
часть потери скорости возникает выше QUIC в RNS/адаптере, но это не изолированный
замер одной библиотеки: также различаются framing, очередь и application streams.
У pure iroh echo имеет собственный QUIC stream; RNS Link делят один stream.
Нельзя приписывать всю разницу одной криптографии или обещать скорость Xray после
простой замены нижнего транспорта. Пять pure iroh прогонов и обе SHA integrity
ячейки успешны: `compare-iroh-{direct,chain}-*.json`, `verify-iroh*-2gib.json`.

**Если сравнивать только speed/CPU, текущий KnotHop проигрывает обоим зрелым стекам.**
Xray в этом тесте одновременно быстрее, дешевле по CPU и имеет меньший хвост RTT.
RNS выигрывает у этой AWG userspace-конфигурации по p95 под нагрузкой, но не по
throughput или CPU/GiB. Это не основание считать kernel AWG медленным.

RNS выбирается ради маршрутизации/сквозного Link через intermediates, а не как
самый дешёвый VPN transport. Подмена продуктового канала на Xray/AWG не сделана.
Следующий предмет оптимизации — профилирование всей RNS/adapter цепочки, а не
ещё большее окно. Сравнение failover, real RTT/loss, обфускации и Android energy
пока отсутствует; Xray HTTPS/Vision direct path требует отдельной нагрузки.

## Воспроизведение и источники

```sh
docker build -f bench/Dockerfile.compare -t knothop-bench:compare bench
CARGO_TARGET_DIR=$HOME/.cache/knothop-target/fork-win256 bench/build_fork.sh
python3 bench/protocol_compare.py xray my-xray --duration 10
python3 bench/protocol_compare.py awg my-awg --hops 2 --duration 10
python3 bench/protocol_compare.py iroh my-iroh --duration 10
python3 bench/comparison_summary.py
```

Сырые данные: `bench/results/protocol-compare/`, KnotHop —
`bench/results/lev-iroh/compare-rawg-*`. Версии, image IDs и SHA исполняемых файлов
записаны в comparator JSON. Старые failed smoke cells сохранены, в медианы не входят.

- [Xray LICENSE v26.7.28](https://raw.githubusercontent.com/XTLS/Xray-core/v26.7.28/LICENSE).
- [Freedom finalRules source](https://raw.githubusercontent.com/XTLS/Xray-core/v26.7.28/proxy/freedom/freedom.go)
  и [configuration](https://raw.githubusercontent.com/XTLS/Xray-core/v26.7.28/infra/conf/freedom.go).
- AWG версии/хеши/лицензии и RandomTrailers limitation: [bench/AWG.md](../bench/AWG.md).
