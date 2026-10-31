#!/usr/bin/env bash
# Build the DMC vault harness into a dex jar so a shell can drive it, and its launcher.
#
#   ./d2/build.sh            -> d2/dist/df-d2.jar, d2/dist/df-d2-launch
#
# The harness sources live in app/src/main/java/df/d2 - the same files the APK compiles -
# so the CLI path here and the app's own path cannot drift. On the device the writer runs
# under app_process, which is what puts framework.jar (and with it the vendor's
# VaultKeeperManager) on the boot classpath; app_process can be pointed at the installed
# APK directly, so this jar is only needed to drive the same code from adb.
set -euo pipefail
cd "$(dirname "$0")"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
[ -d "$SDK" ] || { echo "no Android SDK at $SDK (set ANDROID_HOME)" >&2; exit 1; }
BUILD_TOOLS=$(command ls -d "$SDK"/build-tools/*/ 2>/dev/null | sort -V | tail -1)
[ -n "$BUILD_TOOLS" ] || { echo "no build-tools under $SDK" >&2; exit 1; }

mkdir -p dist
CLASSES=$(mktemp -d)
trap 'rm -rf "$CLASSES"' EXIT

javac --release 11 -Xlint:all -d "$CLASSES" ../app/src/main/java/df/d2/*.java
"${BUILD_TOOLS}d8" --release --min-api 26 --output dist/df-d2.jar \
    "$CLASSES"/df/d2/*.class
echo "built dist/df-d2.jar (d8 from ${BUILD_TOOLS})"

# The launcher exists to choose argv[0], which is the name VaultKeeperService reads out of
# /proc/<pid>/cmdline when it decides whether it may hand out the vault. Same source the
# APK packages as libdf-d2-launch.so via CMakeLists.txt.
NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_NDK:-$SDK/ndk}}"
NDK=$(command ls -d "$NDK_ROOT"/*/ 2>/dev/null | sort -V | tail -1)
[ -n "$NDK" ] || { echo "no NDK under $NDK_ROOT (set ANDROID_NDK_HOME)" >&2; exit 1; }
HOST=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$HOST" in darwin) HOST=darwin-x86_64 ;; linux) HOST=linux-x86_64 ;; *)
    echo "unsupported build host: $(uname -s)" >&2; exit 1 ;;
esac
"$NDK/toolchains/llvm/prebuilt/$HOST/bin/aarch64-linux-android21-clang" \
    -std=gnu11 -O2 -Wall -Wextra -o dist/df-d2-launch ../app/src/main/jni/d2_launch.c
echo "built dist/df-d2-launch (NDK ${NDK})"
