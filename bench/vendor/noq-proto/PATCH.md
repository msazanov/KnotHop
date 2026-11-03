# Локальная правка noq-proto 1.3.0

Пакет `noq-proto` 1.3.0 с crates.io (MIT OR Apache-2.0), локальные правки:

1. `src/connection/mod.rs` (`current_mtu`):
   В режиме multipath при наличии путей со статусом `PathStatus::Available` расчёт текущего MTU соединения
   производится как минимум по путям `Available` (активным для передачи данных), а не по всем открытым путям.
   Ранее наличие тёплого запасного пути (custom/mesh или relay с начальным MTU 1200) опускало бюджет
   датаграмм всего соединения до ~1162 Б, из-за чего все пакеты 1280..1328 Б отбрасывались с `TooLarge`
   даже при активном прямом пути (MTU 1452..1500).

2. `src/connection/mod.rs` (`poll_transmit`) и `datagrams.rs`:
   При изменении доступного бюджета очередь очищается от превышающих его датаграмм ДО планирования
   отправки. Предел тот же, что у `Datagrams::max_size()`, точное равенство допустимо. Освобождение очереди
   будит ожидающего отправителя. Число отброшенных пакетов — `ConnectionStats::datagram_mtu_drops`.
   Это потеря уже принятой в очередь датаграммы, а не `TooLarge` на вызове send и не доставка через fallback.
   Прежняя локальная попытка отбрасывать внутри `write` с угаданным заголовком 10 Б удалена:
   до `write` можно не дойти, если слишком большая голова очереди запретила её планирование.

3. `FrameStats::authenticated_progress()` — счётчик принятых ACK/PATH_ACK/DATAGRAM/STREAM/PING/PATH_RESPONSE
   для наблюдения живости после handshake. Счётчики фреймов обновляются после AEAD и dedup; сырые
   `udp_rx` включают неаутентифицированные пакеты и повторы и для этого непригодны. Это контакт,
   не гарантия ответа на конкретный прикладной запрос и не процент потерь.
   `FrameStats::ack_eliciting_progress()` — отправленные кадры, требующие ответа пира
   (DATAGRAM/STREAM/PING/PATH_CHALLENGE/IMMEDIATE_ACK), для сторожка застоя iroh; ACK-only исключены.

Тесты: `authenticated_progress_ignores_corruption_and_packet_replay`,
`warm_backup_mtu_and_queued_datagrams_after_failover`,
`mtu_queue_pruning_preserves_boundary_and_unblocks_smaller_datagrams`.
Запуск из корня через `bench/cargo_fork.sh rns-iroh-node test --manifest-path "$PWD/bench/vendor/noq-proto/Cargo.toml" --locked --lib`.

Ограничение: активный путь с MTU 1200 по-прежнему не вмещает VPN-датаграмму 1328 Б. Правки не заменяют
решение PMTU/фрагментации и не дают основания удалять Link fallback. Black-hole detection не отключён.

Подключён в `bench/rns-iroh-node/Cargo.toml` и `bench/android/native/Cargo.toml` через `[patch.crates-io]`.

4. `src/knothop.rs`, `connection/paths.rs` (`PathData::new`): потолок UDP-пакета для путей по адресам, которые пометило приложение
   (`knothop::set_path_mtu_cap(fn(&SocketAddr) -> Option<u16>)`). `initial_mtu` и `MtuDiscoveryConfig::upper_bound` пути ограничиваются
   потолком (не ниже `min_mtu`). Нужно custom-транспорту mesh: он не сообщает MTU, а пакет больше датаграммы соседского QUIC теряется молча;
   серии таких потерь детектор чёрной дыры принимал за MTU и сбрасывал путь в 1200 на `black_hole_cooldown` (60 с). Без вызова `set_path_mtu_cap` поведение прежнее.

5. Лимиты NAT traversal (QNT) на соединение: `src/n0_nat_traversal.rs` (`Guard`, константы), `connection/mod.rs` (поле `nat_guard`, обработчики `Frame::ReachOut`/`Frame::AddAddress`, `send_nat_traversal_path_challenge`), `connection/stats.rs` (`ConnectionStats::nat_probes_suppressed`).
   Причина: пир, открывший QUIC-соединение (допуск у нас прикладной), мог слать REACH_OUT с растущим `round`; каждый раунд сбрасывал счётчики попыток (9 проб на адрес, до `MAX_QNT_ADDRESSES`=32 адресов) и сервер снова слал PATH_CHALLENGE на названные адреса, в т.ч. публичные чужие (отражение/усиление). Ограничения нет ни по частоте раундов, ни по общему числу проб (измерение в тесте: 4800 проб за 20 с модельного времени от одного пира с 8 адресами). Клиентская сторона: ADD_ADDRESS с новым адресом (или новым `seq_no` после REMOVE) сбрасывает счётчик попыток.
   - `MIN_NAT_ROUND_INTERVAL` = 5 с: REACH_OUT нового (большего) раунда принимается не чаще раза в 5 с на соединение; лишние кадры молча игнорируются, соединение не закрывается. Кадры текущего раунда не затрагиваются. (iroh пробивает заново не чаще 1 раза в 3..60 с; при сетевой смене раунд клиента может быть проигнорирован сервером, следующий принимается — клиент в любом случае зондирует адреса сервера сам.)
   - Бюджет проб: токен-бакет `NAT_PROBE_BURST`=256 / `NAT_PROBE_REFILL`=60 с (≈4,3 проб/с в среднем) на соединение, обе стороны. Исчерпание — проба снимается с очереди (`drop_pending_probe`), отправка не делается; штатные ретраи берут из того же бакета.
   - ADD_ADDRESS: бакет `max_remote_addresses + 16` (=48 при iroh), пополнение `NAT_ADDR_CHANGES_PER_MIN`=16 в минуту; тратится на вставку нового адреса и замену адреса известного `seq_no`; повтор уже известного адреса не тратится. Начальная выдача всех адресов после рукопожатия не режется. При исчерпании кадр игнорируется.
   - Все отказы тихие и считаются в `ConnectionStats::nat_probes_suppressed` (раунды + пробы + смены адреса). В knothopd: `nat_probes_suppressed` в `dataplane.stats()` и в `path_json` (`mesh.rs`).
   Не закрыто: лимиты на соединение, а не на пира/узел: N соединений от одного ключа/адреса дают N бюджетов; нужен общий лимит числа соединений (прикладной). Фильтр приватных адресов (iroh правка 3) независим и остаётся.
   Тесты (`tests/multipath.rs`): `nat_reach_out_round_flood_is_limited`, `nat_probe_budget_caps_sustained_rate`, `nat_add_address_flood_is_limited`, `nat_second_round_after_interval_still_opens_path`; без Guard первые три падают.
