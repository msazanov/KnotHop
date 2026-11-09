# Локальная правка noq 1.3.0

Исходники `noq` 1.3.0 с crates.io (MIT OR Apache-2.0; удалены `examples/`, `tests/` и локальный `Cargo.lock`).

1. `src/path.rs`: `Path::knothop_recover_stalled` вызывает `noq_proto::Connection::knothop_recover_stalled_path` для переочередивания неподтверждённых пакетов пути, признанного сторожком застоявшимся, без закрытия самого пути.
2. `src/connection.rs`, `src/lib.rs`: `read_datagram_with_path` / `ReadDatagramWithPath` и `send_datagram_on_path` пробрасывают привязку датаграмм к аутентифицированному `PathId` для объёмной (>1 МиБ) проверки прямого канала без переключения рабочего транзита.
