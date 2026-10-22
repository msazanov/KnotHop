#!/usr/bin/env bash
# Сборка тестового APK (arm64-v8a) без Gradle: cargo (NDK clang) -> javac -> d8 -> aapt2 -> zipalign -> apksigner.
# Использование: build.sh [meas|vpn]   (meas - приложение замеров, vpn - VPN-приложение)
# Результат: $OUT/rawgmeas.apk или $OUT/rawgvpn.apk (по умолчанию ~/.cache/rawg-android/)
# Окружение: KNOTHOP_KS/KNOTHOP_KEY_ALIAS/KNOTHOP_KS_PASS - релизная подпись (PKCS12), KNOTHOP_RELEASE=1 берёт
# файлы из ~/.config/knothop/release; KNOTHOP_VERSION_CODE/KNOTHOP_VERSION_NAME - версия в рабочей копии манифеста.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="${1:-meas}"
case "$APP" in meas) SRC="$HERE/app"; PKG=com/rawg/meas ;; vpn) SRC="$HERE/vpn"; PKG=com/rawg/vpn ;; *) echo "meas|vpn"; exit 1 ;; esac
# Подпись. Без KNOTHOP_KS - локальный debug.keystore, как раньше. Пароль релизного ключа идёт только через
# окружение (apksigner env:), не в argv и не в журнал. Релизный ключ не сочетается с лабораторными сборками.
RELEASE_DIR="$HOME/.config/knothop/release"
if [ "${KNOTHOP_RELEASE:-0}" = 1 ]; then
  KNOTHOP_KS="${KNOTHOP_KS:-$RELEASE_DIR/knothop-release.p12}"
  KNOTHOP_KEY_ALIAS="${KNOTHOP_KEY_ALIAS:-$(cat "$RELEASE_DIR/alias")}"
  KNOTHOP_KS_PASS="$(cat "$RELEASE_DIR/store.pass")"
  export KNOTHOP_KS_PASS
fi
if [ -n "${KNOTHOP_KS:-}" ]; then
  if [ "$APP" != vpn ]; then echo "релизная подпись только для vpn" >&2; exit 1; fi
  if [ "${RAWG_LAB:-0}" = 1 ] || [ "${RAWG_PROFILEABLE:-0}" = 1 ]; then
    echo "релизная подпись не совместима с RAWG_LAB и RAWG_PROFILEABLE" >&2; exit 1
  fi
  : "${KNOTHOP_KEY_ALIAS:?нужен KNOTHOP_KEY_ALIAS}" "${KNOTHOP_KS_PASS:?нужен KNOTHOP_KS_PASS}"
fi
# в CI (CI=true выставляет GitHub Actions) собирается только обычная сборка
if [ "${CI:-}" = true ]; then
  if [ "${RAWG_LAB:-0}" = 1 ] || [ "${RAWG_PROFILEABLE:-0}" = 1 ]; then
    echo "в CI запрещены RAWG_LAB и RAWG_PROFILEABLE" >&2; exit 1
  fi
fi
# версия проверяется до долгой сборки; подстановка в манифест - ниже
if [ -n "${KNOTHOP_VERSION_CODE:-}" ] && [[ ! "$KNOTHOP_VERSION_CODE" =~ ^[0-9]+$ ]]; then
  echo "KNOTHOP_VERSION_CODE: нужно целое число" >&2; exit 1
fi
if [ -n "${KNOTHOP_VERSION_NAME:-}" ] && [[ ! "$KNOTHOP_VERSION_NAME" =~ ^[0-9A-Za-z._-]+$ ]]; then
  echo "KNOTHOP_VERSION_NAME: допустимы буквы, цифры, точка, _ и -" >&2; exit 1
fi
export PATH="$HOME/.cargo/bin:$PATH"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
NDK="${ANDROID_NDK_HOME:-$(ls -d "$SDK"/ndk/* | sort -V | tail -1)}"
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
PLATFORM="$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar"
API=26
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
CLANG="$TOOLCHAIN/bin/aarch64-linux-android${API}-clang"
FORK="${LEVICULUM_FORK:-$HOME/dev/leviculum}"
# воспроизводимый штамп leviculum-core/build.rs: время сборки берём из HEAD форка
# (SOURCE_DATE_EPOCH можно переопределить снаружи)
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$FORK" log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
  export SOURCE_DATE_EPOCH
fi
OUT="${OUT:-$HOME/.cache/rawg-android}"
TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/rawg-target/android}"
mkdir -p "$OUT"
[ -x "$CLANG" ] || { echo "нет $CLANG"; exit 1; }

echo "== Rust (aarch64-linux-android, API $API)"
export CC_aarch64_linux_android="$CLANG"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$TOOLCHAIN/bin/llvm-ar"
export RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8 -C link-arg=-Wl,-z,max-page-size=16384"
# RAWG_SYMBOLS=1: .so с символами (для simpleperf), по умолчанию strip
if [ "${RAWG_SYMBOLS:-0}" = "1" ]; then export CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1; TARGET_DIR="$TARGET_DIR-sym"; fi
EXTRA=()
# RAWG_UDPSTATS=1: счётчики sendmsg/recvmmsg (локальный patch noq-udp из ~/.cache/rawg-patches), в отдельный каталог сборки
if [ "${RAWG_UDPSTATS:-0}" = "1" ]; then EXTRA=(--features udp-stats --config "patch.crates-io.noq-udp.path=\"$HOME/.cache/rawg-patches/noq-udp\""); TARGET_DIR="$TARGET_DIR-udp"; fi
# RAWG_FEATURES="mimalloc ...": дополнительные фичи нативной части, отдельный каталог сборки
RAWG_FEATURES="${RAWG_FEATURES-mimalloc}"   # mimalloc по умолчанию: -3…-6% циклов на ГиБ (W20); RAWG_FEATURES="" чтобы выключить
if [ -n "${RAWG_FEATURES:-}" ]; then EXTRA+=(--features "${RAWG_FEATURES// /,}"); TARGET_DIR="$TARGET_DIR-$(echo "$RAWG_FEATURES" | tr " ," "__")"; fi
( cd "$HERE/native" && CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release --target aarch64-linux-android "${EXTRA[@]}" \
    --config "patch.\"https://codeberg.org/Lew_Palm/Leviculum\".leviculum-std.path=\"$FORK/leviculum-std\"" )
SO="$TARGET_DIR/aarch64-linux-android/release/librawgmeas.so"
ls -l "$SO"

echo "== Java"
# ZXing Core 3.5.3 (Apache-2.0): кодирование и разбор QR приглашения, только для vpn; jar закреплён по sha256 (sha1 ca134921... совпадает с Maven Central)
QR_JAR="$OUT/zxing-core-3.5.3.jar"
QR_SHA=8d8064c1636fdaef7189dd9055c7d59950a8940a12f2293956446ec3c109fd82
CP="$PLATFORM"
if [ "$APP" = vpn ]; then
  if [ ! -f "$QR_JAR" ]; then
    curl --fail --location --silent --show-error https://repo.maven.apache.org/maven2/com/google/zxing/core/3.5.3/core-3.5.3.jar -o "$QR_JAR.part"
    echo "$QR_SHA  $QR_JAR.part" | sha256sum -c -
    mv "$QR_JAR.part" "$QR_JAR"
  fi
  echo "$QR_SHA  $QR_JAR" | sha256sum -c -
  CP="$PLATFORM:$QR_JAR"
fi
# RAWG_LAB=1: лабораторные интенты и подробные логи. RAWG_PROFILEABLE=1:
# только shell-профилирование, без LAB_BUILD, интентов и подробного logcat.
# Обычная сборка по умолчанию не разрешает ни то ни другое.
SRC_WORK="$OUT/src-$APP"; rm -rf "$SRC_WORK"; mkdir -p "$SRC_WORK"; cp -r "$SRC"/. "$SRC_WORK"/
# версия подставляется только в рабочую копию манифеста; исходник не меняется; без переменных - как в исходнике
if [ -n "${KNOTHOP_VERSION_CODE:-}" ]; then
  sed -i "s/android:versionCode=\"[0-9]*\"/android:versionCode=\"$KNOTHOP_VERSION_CODE\"/" "$SRC_WORK/AndroidManifest.xml"
  grep -q "android:versionCode=\"$KNOTHOP_VERSION_CODE\"" "$SRC_WORK/AndroidManifest.xml" || { echo "versionCode не подставился" >&2; exit 1; }
fi
if [ -n "${KNOTHOP_VERSION_NAME:-}" ]; then
  sed -i "s/android:versionName=\"[^\"]*\"/android:versionName=\"$KNOTHOP_VERSION_NAME\"/" "$SRC_WORK/AndroidManifest.xml"
  grep -q "android:versionName=\"$KNOTHOP_VERSION_NAME\"" "$SRC_WORK/AndroidManifest.xml" || { echo "versionName не подставился" >&2; exit 1; }
fi
if [ "${RAWG_LAB:-0}" = "1" ]; then
  sed -i 's/LAB_BUILD = false/LAB_BUILD = true/' "$SRC_WORK"/java/$PKG/*.java
  grep -rq "LAB_BUILD = true" "$SRC_WORK"/java/$PKG/*.java || { echo "LAB_BUILD не включился: проверь формат строки в Util.java" >&2; exit 1; }
  sed -i 's#<application #<application android:debuggable="false" #' "$SRC_WORK/AndroidManifest.xml"
elif [ "${RAWG_PROFILEABLE:-0}" != "1" ]; then
    sed -i '/<profileable/d' "$SRC_WORK/AndroidManifest.xml"
fi
SRC="$SRC_WORK"

W="$OUT/work-$APP"; rm -rf "$W"; mkdir -p "$W/classes" "$W/dex" "$W/stage/lib/arm64-v8a"
javac --release 8 -Xlint:-options -cp "$CP" -d "$W/classes" "$SRC"/java/$PKG/*.java
DEXIN=$(find "$W/classes" -name '*.class'); [ "$APP" = vpn ] && DEXIN="$DEXIN $QR_JAR"
"$BT/d8" --release --min-api $API --lib "$PLATFORM" --output "$W/dex" $DEXIN

echo "== APK"
"$BT/aapt2" link -o "$W/base.apk" -I "$PLATFORM" --manifest "$SRC/AndroidManifest.xml" --min-sdk-version $API --target-sdk-version 34
cp "$W/dex/classes.dex" "$W/stage/"
if [ "$APP" = vpn ]; then mkdir -p "$W/stage/assets"; cp "$HERE/LICENSE-ZXing.txt" "$W/stage/assets/"; fi
cp "$SO" "$W/stage/lib/arm64-v8a/"
# снимок состояния форка, из которого собрана .so
bash "$HERE/../../deploy/fork-manifest.sh" "$W/FORK-MANIFEST.txt"
( cd "$W/stage" && zip -q -r "$W/base.apk" classes.dex lib && if [ -d assets ]; then zip -q -r "$W/base.apk" assets; fi )
cp "$W/FORK-MANIFEST.txt" "$W/stage/FORK-MANIFEST.txt"
( cd "$W/stage" && zip -q "$W/base.apk" FORK-MANIFEST.txt )
"$BT/zipalign" -f -p 4 "$W/base.apk" "$W/aligned.apk"
SIGNED="$OUT/rawg$APP.apk"
if [ -n "${KNOTHOP_KS:-}" ]; then
  "$BT/apksigner" sign --ks "$KNOTHOP_KS" --ks-type PKCS12 --ks-key-alias "$KNOTHOP_KEY_ALIAS" \
    --ks-pass env:KNOTHOP_KS_PASS --key-pass env:KNOTHOP_KS_PASS --out "$SIGNED" "$W/aligned.apk"
  echo "подпись: релизный ключ (PKCS12)"
else
  KS="$OUT/debug.keystore"
  [ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass android -keypass android -alias rawg -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=rawg test" >/dev/null 2>&1
  "$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android --out "$SIGNED" "$W/aligned.apk"
  echo "подпись: локальный debug.keystore (не релизная)"
fi
# --print-certs: SHA-256 сертификата подписи публичен и нужен для сверки релиза
"$BT/apksigner" verify --verbose --print-certs "$SIGNED"
ls -l "$SIGNED"
