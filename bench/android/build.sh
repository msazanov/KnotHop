#!/usr/bin/env bash
# Сборка тестового APK (arm64-v8a) без Gradle: cargo (NDK clang) -> javac -> d8 -> aapt2 -> zipalign -> apksigner.
# Использование: build.sh [meas|vpn]   (meas - приложение замеров, vpn - VPN-приложение)
# Результат: $OUT/rawgmeas.apk или $OUT/rawgvpn.apk (по умолчанию ~/.cache/rawg-android/)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="${1:-meas}"
case "$APP" in meas) SRC="$HERE/app"; PKG=com/rawg/meas ;; vpn) SRC="$HERE/vpn"; PKG=com/rawg/vpn ;; *) echo "meas|vpn"; exit 1 ;; esac
export PATH="$HOME/.cargo/bin:$PATH"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
NDK="${ANDROID_NDK_HOME:-$(ls -d "$SDK"/ndk/* | sort -V | tail -1)}"
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
PLATFORM="$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar"
API=26
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
CLANG="$TOOLCHAIN/bin/aarch64-linux-android${API}-clang"
FORK="${LEVICULUM_FORK:-$HOME/dev/leviculum}"
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
( cd "$W/stage" && zip -q -r "$W/base.apk" classes.dex lib $( [ -d assets ] && echo assets ) )
cp "$W/FORK-MANIFEST.txt" "$W/stage/FORK-MANIFEST.txt"
( cd "$W/stage" && zip -q "$W/base.apk" FORK-MANIFEST.txt )
"$BT/zipalign" -f -p 4 "$W/base.apk" "$W/aligned.apk"
KS="$OUT/debug.keystore"
[ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -storepass android -keypass android -alias rawg -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=rawg test" >/dev/null 2>&1
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android --out "$OUT/rawg$APP.apk" "$W/aligned.apk"
"$BT/apksigner" verify --verbose "$OUT/rawg$APP.apk" | head -4
ls -l "$OUT/rawg$APP.apk"
