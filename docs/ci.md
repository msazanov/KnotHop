# CI KnotHop

Один workflow `.github/workflows/ci.yml` с четырьмя группами job:

- **Тесты** (`tests`) - на каждом `push`, `pull_request` и ручном запуске: `cargo test --lib`, Python-тесты `deploy/test_push.py` и `deploy/test_sanitize_public.py` (unittest), `bash -n` и ShellCheck (уровень warning) для `deploy/*.sh` и `bench/android/build.sh`.
- **Сборки** (`host`, `u2204`, `apk`) - только на `main` (push или ручной запуск с `main`) и только после успешных тестов.
- **Релиз** (`release`) - только на `main`. Тег `v0.1.<номер запуска>`, релиз с `knothopd`, `knothopd-u2204`, `knothop.apk`, `SHA256SUMS` и `FORK-MANIFEST.txt`. Это единственная job с правом `contents: write`.

Права по умолчанию - `contents: read`. Секреты подписи читаются только в job `apk` и только на `main`; `pull_request` их не получает.

## Форк Leviculum

Файл `deploy/leviculum.ref` содержит полный SHA коммита форка `github.com/msazanov/leviculum`. CI клонирует форк по этому SHA в `leviculum/` и подключает `leviculum-std` через cargo patch. Вендорной копии в репозитории нет.

`deploy/ci-build.sh` перед сборкой проверяет, что HEAD форка совпадает с `deploy/leviculum.ref`. `SOURCE_DATE_EPOCH` берётся из коммита форка, поэтому при одном коммите штамп сборки одинаков.

### Синхронизация с апстримом

`.github/workflows/leviculum-sync.yml` (раз в неделю и вручную) вызывает `deploy/leviculum-sync.sh prepare`: клонирует форк на закреплённом SHA с полной историей, подтягивает `master` апстрима (codeberg `Lew_Palm/Leviculum`) и пробует слияние. Исходы: `uptodate` - ничего; `conflict` - issue со списком файлов; `merged` - сборка и тесты кандидата (`check_fork_graph.sh`, `cargo test --lib`). При красных проверках открывается issue, при зелёных и наличии секрета `LEVICULUM_FORK_DEPLOY_KEY` (deploy key с записью, добавлен только в `msazanov/leviculum`) ветка `knothop/upstream-ДАТА-sha8` пушится в форк и открывается PR в KnotHop, меняющий `deploy/leviculum.ref`. Без секрета - только сводка. В main ничего не сливается само: релиз с main уходит на узлы автообновлением, а код апстрима чужой. В теле PR перечислены затронутые чувствительные пути (crypto, GCM, Link, пакеты, identity). PR от `GITHUB_TOKEN` не запускает CI: запустить вручную. Настройка «Allow GitHub Actions to create and approve pull requests» включена 27.10. Первое слияние (170 коммитов апстрима против 37 наших) даёт конфликты в `link_management.rs` и `packet.rs`, его делают вручную.

## Сборка бинарников

- `deploy/ci-build.sh host КАТАЛОГ` - `knothopd` на хосте раннера (Ubuntu 24.04); пишет также `FORK-MANIFEST.txt`.
- `deploy/ci-build.sh u2204 КАТАЛОГ` - `knothopd-u2204` в контейнере `ubuntu:22.04` из `deploy/Dockerfile.u2204`. Toolchain ставит `rustup-init`, который проверяется по SHA-256 с `static.rust-lang.org`.

Скрипт проверяет, что `knothopd-u2204` требует glibc не новее 2.35.

Бинарники CI не совпадают побайтово с локальными сборками `deploy/build.sh`: другой toolchain и другой путь исходников. Совпадение достигается только при одинаковом окружении.

## APK

`bench/android/build.sh vpn` собирает обычную сборку (без лабораторных режимов). В CI `KNOTHOP_LAB` и `KNOTHOP_PROFILEABLE` запрещены: при `CI=true` скрипт завершается с ошибкой.

Подпись: если задан `KNOTHOP_KS` (путь к PKCS12), `apksigner` берёт пароли через `env:`, не через argv. Без него используется локальный `debug.keystore`. Ручная сборка релизным ключом: `KNOTHOP_RELEASE=1 ./build.sh vpn`.

Версия: `KNOTHOP_VERSION_CODE` (целое) и `KNOTHOP_VERSION_NAME` подставляются только в рабочую копию манифеста. В CI versionCode - номер запуска, versionName - `0.1.<номер запуска>`.

Секреты репозитория:

- `KNOTHOP_KEYSTORE_B64` - PKCS12 в base64;
- `KNOTHOP_KEYSTORE_PASS` - пароль хранилища и ключа;
- `KNOTHOP_KEY_ALIAS` - алиас ключа.

Файл ключа декодируется в `$RUNNER_TEMP` с правами 0600 и удаляется в конечном шаге. SHA-256 сертификата подписи печатается в журнал: он публичен и нужен для сверки.

## Публикационная копия

`deploy/sanitize_public.py` создаёт публичную копию. Форк в неё не вендорится: `NOTICE-KNOTHOP.md` указывает коммит, а `--leviculum-fork` проверяет, что форк стоит на этом коммите и без незакоммиченных правок.

```sh
python3 deploy/sanitize_public.py /путь/к/частному/дереву /новый/путь/KnotHop --leviculum-fork /путь/к/leviculum
python3 -m unittest deploy/test_push.py deploy/test_sanitize_public.py
```

Скрипт исключает локальные state, инвентари, бинарники, результаты, архивные и операционные документы и ревью; адреса и идентификаторы в текстовых исходниках заменяются плейсхолдерами. Отдельный [whitelist](../deploy/public-rns-whitelist.txt) содержит только публичные RNS-транспорты. После генерации запускается сканер. Отдельно: `python3 deploy/sanitize_public.py ИСХОДНИК КОПИЯ --scan`.

## Локальные проверки

```sh
python3 -m unittest deploy/test_push.py deploy/test_sanitize_public.py
for script in deploy/*.sh bench/android/build.sh; do bash -n "$script"; shellcheck -S warning -x "$script"; done
export LEVICULUM_FORK=/путь/к/checkout/leviculum   # должен стоять на коммите из deploy/leviculum.ref
cd bench/rns-iroh-node
cargo test --lib --config "patch.\"https://codeberg.org/Lew_Palm/Leviculum\".leviculum-std.path=\"$LEVICULUM_FORK/leviculum-std\""
```
