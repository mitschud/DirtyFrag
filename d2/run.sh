#!/usr/bin/env bash
# Push the harness to the attached device and run it as root. Read-only unless you ask.
#
#   ./d2/run.sh                # status      - just read the vault
#   ./d2/run.sh authorize      # one read-modify-verify, sets the AT-authorisation byte
#   ./d2/run.sh clear          # the same, clearing the byte again
#
# The harness needs framework.jar on the boot classpath to see the vendor's
# VaultKeeperManager, so the runner borrows BOOTCLASSPATH from the running system_server -
# the same classpath a real system service gets. The app takes the same route without a
# runner script, pointing app_process at its own installed APK; see D2Writer.
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-status}"
case "$MODE" in
    status|authorize|clear) ;;
    *) echo "usage: $0 [status|authorize|clear]" >&2; exit 2 ;;
esac

JAR=dist/df-d2.jar
LAUNCHER=dist/df-d2-launch
[ -f "$JAR" ] && [ -f "$LAUNCHER" ] || ./build.sh

DEV_JAR=/data/local/tmp/df-d2.jar
DEV_RUN=/data/local/tmp/df-d2-run.sh
LOCAL=$(mktemp)
trap 'rm -f "$LOCAL"' EXIT

cat > "$LOCAL" <<'RUN'
#!/system/bin/sh
EN=/proc/$(pidof system_server)/environ
for name in BOOTCLASSPATH DEX2OATBOOTCLASSPATH ANDROID_ROOT ANDROID_DATA; do
    value=$(cat "$EN" | tr '\0' '\n' | sed -n "s/^${name}=//p")
    [ -n "$value" ] && export "$name=$value"
done
# VaultKeeperService.getPackageName() authorises a caller whose command line (read by libvkjni
# out of /proc/<pid>/cmdline) is "system_server"; any other caller has to be a platform-signed
# app that ActivityManager knows about. The launcher picks argv[0] and execs app_process64.
exec /data/local/tmp/df-d2-launch /data/local/tmp/df-d2.jar "$1" "$3" "$2"
RUN

# The vaultkeeper service grants the vault to the platform uid, not to root, so the harness
# runs as uid 1000. Override with D2_UID / D2_NAME when experimenting.
RUN_UID="${D2_UID:-1000}"
RUN_NAME="${D2_NAME:-system_server}"

adb push "$JAR" "$DEV_JAR" >/dev/null
adb push "$LAUNCHER" /data/local/tmp/df-d2-launch >/dev/null
adb shell chmod 755 /data/local/tmp/df-d2-launch >/dev/null
adb push "$LOCAL" "$DEV_RUN" >/dev/null
echo "running df.d2.Harness $MODE (uid $RUN_UID, process name $RUN_NAME) ..."
STATUS=0
adb shell "su -c 'sh $DEV_RUN $MODE $RUN_NAME $RUN_UID'" || STATUS=$?
adb shell "rm -f $DEV_RUN /data/local/tmp/df-d2-launch" >/dev/null
exit $STATUS
