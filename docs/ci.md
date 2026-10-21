# CI KnotHop

На `push` и `pull_request` workflow `.github/workflows/ci.yml` запускает библиотечные Rust-тесты, `pytest` для `deploy/test_push.py`, `bash -n` и ShellCheck скриптов деплоя, сборки `rawgd` на Ubuntu 24.04 и `rawgd-u2204` на Ubuntu 22.04, а также VPN APK. Для бинарников проверяется верхняя версия GLIBC; каждый артефакт сопровождается `SHA256SUMS`. APK подписывается временным debug-ключом, который создаётся штатным `build.sh` в каталоге job и не попадает в репозиторий. Секреты и раскатка на серверы не используются.

CI и локальная сборка используют вендор-копию `third_party/leviculum`; Codeberg остаётся первоисточником, но для сборки доступ к нему не требуется. Cargo patch перекрывает закреплённую git-зависимость.

## Локальный запуск

```sh
python3 -m pytest -q deploy/test_push.py
for script in deploy/*.sh; do bash -n "$script"; shellcheck -x "$script"; done
cd bench/rns-iroh-node
cargo test --lib --config 'patch."https://codeberg.org/Lew_Palm/Leviculum".leviculum-std.path="../../third_party/leviculum/leviculum-std"'
```

Android-сборка требует JDK 17, Android SDK platform/build-tools, NDK 29, Rust target `aarch64-linux-android`, а для VPN-приложения скачивает ZXing Core 3.5.3 и проверяет его SHA-256. Локальная команда: `cd bench/android && ./build.sh vpn`.

## Подготовка публикационной копии

Не публикуйте рабочее дерево напрямую. Перед каждым коммитом в публичный репозиторий создавайте новый каталог:

```sh
python3 deploy/sanitize_public.py /путь/к/частному/исходному/дереву /новый/путь/KnotHop --leviculum-fork /путь/к/Leviculum
python3 -m pytest -q /новый/путь/KnotHop/deploy/test_push.py
```

Скрипт исключает локальные state, инвентари, бинарники, результаты, архивные/операционные документы и ревью; адреса и идентификаторы, оставшиеся в текстовых исходниках, заменяются плейсхолдерами. Отдельный [whitelist](../deploy/public-rns-whitelist.txt) содержит только публичные RNS-транспорты, чьи адреса разрешено сохранить. После генерации запускается тот же сканер автоматически; отдельный повторный запуск: `python3 deploy/sanitize_public.py /путь/к/частному/исходному/дереву /новый/путь/KnotHop --scan`. Владелец переносит в GitHub только проверенное содержимое этой копии. Скрипт отказывается перезаписывать существующий каталог.

## Ограничения воспроизводимости

Патчи в `docs/patches/` сохранены как исторические справочные материалы; они не применяются CI, поскольку текущее рабочее состояние форка включено в `third_party/leviculum/`.

APK в CI — только debug-сборка для проверки компиляции, не канал распространения и не production-подпись. Документация экспериментов и ревью безопасности отдельно требуют решения о редакции до публичной публикации.
