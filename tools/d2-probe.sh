#!/usr/bin/env bash
# Read-only probe for the DMC / vaultkeeper writer design in docs/d2-download-mode-writer.md.
# Nothing here writes: no vault write, no settings write, no module install.
#
#   ./tools/d2-probe.sh                 # uses the one device adb sees
#   ./tools/d2-probe.sh <serial>        # -s <serial>
#
# The log lands in d2-probe-<model>-<date>.log next to where you run it.
set -uo pipefail

SERIAL="${1:-}"
ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

DEV=/data/local/tmp/d2-probe.sh
# Host-side scratch: the heredoc below lands here first, then gets pushed to $DEV.
TMP=$(mktemp "${TMPDIR:-/tmp}/d2-probe.XXXXXX") || exit 1
trap 'rm -f "$TMP"' EXIT
MODEL=$("${ADB[@]}" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
[ -z "$MODEL" ] && { echo "no device through adb (is USB debugging on?)" >&2; exit 1; }
LOG="d2-probe-${MODEL// /_}-$(date +%Y%m%d-%H%M).log"

cat > "$TMP" <<'PROBE'
#!/system/bin/sh
# Runs as root on the device. Read-only. toybox sh, so keep it plain.
sec() { printf '\n========== %s ==========\n' "$1"; }

sec "build"
getprop ro.product.model
getprop ro.product.device
getprop ro.build.fingerprint
getprop ro.build.version.incremental
getprop ro.build.version.release
getprop ro.bootmode
getprop ro.boot.flash.locked
getprop ro.boot.verifiedbootstate

sec "props mentioning vault / dmc / defex / download / fus"
getprop | grep -iE 'vault|dmc|defex|download|fus|odin|rpm' | head -40

sec "selinux"
getenforce
id

sec "services: vaultkeeper / dmc / fus"
service list | grep -iE 'vault|dmc|fus'
printf 'check vaultkeeper: '; service check vaultkeeper
printf 'check DmcService: ';  service check DmcService
echo "--- dumpsys -l"
dumpsys -l | grep -iE 'vault|dmc|fus'

sec "which package holds ACCESS_VAULTKEEPER_SERVICE"
pm list permissions -f | grep -iA8 vaultkeeper
echo "--- grant table slice (bounded)"
dumpsys package permission android.permission.ACCESS_VAULTKEEPER_SERVICE 2>/dev/null | head -30
dumpsys package 2>/dev/null | grep -in -B2 -A2 ACCESS_VAULTKEEPER_SERVICE | head -60

sec "where is VaultKeeperManager / DmcService"
for j in $(find /system /system_ext /product /apex -maxdepth 4 -name '*.jar' 2>/dev/null | head -60); do
    a=$(grep -ac VaultKeeperManager "$j" 2>/dev/null)
    b=$(grep -ac com.android.server.DmcService "$j" 2>/dev/null)
    [ "${a:-0}" != "0" ] || [ "${b:-0}" != "0" ] && printf '%s vaultkeeper=%s dmc=%s\n' "$j" "${a:-0}" "${b:-0}"
done

sec "vendor HALs / binaries touching vaultkeeper"
ls /vendor/bin/hw 2>/dev/null | grep -iE 'vault|dmc|fus|rpm'
lshal 2>/dev/null | grep -iE 'vault|dmc' | head -20
grep -riE 'vaultkeeper' /vendor/etc/vintf/manifest.xml 2>/dev/null | head
ls -l /vendor/lib/hw 2>/dev/null | grep -i vault
ls -l /vendor/bin 2>/dev/null | grep -iE 'vault|vcks|dmc'

sec "system_server classpath (what an app_process harness would need)"
SSP=$(cat /proc/$(pidof system_server)/environ 2>/dev/null | tr '\0' '\n' | grep -i classpath)
printf '%s\n' "${SSP:-not readable or not found}"
ls -l /system/bin/app_process64 2>/dev/null

sec "can su run as uid 1000, and in which context"
for arg in "-o 1000" "--uid 1000" "-u 1000" "1000 2000"; do
    printf 'su %s -c id -> ' "$arg"
    su $arg -c id 2>&1 | head -1
done
echo "--- resulting context"
su -o 1000 -c 'ps -Z -p $$$$' 2>&1 | head -3
su -c 'id' 2>&1 | head -1

sec "root manager"
su -v 2>/dev/null; su --version 2>/dev/null
ls -la /data/adb 2>/dev/null | head -20
echo "--- installed modules"
ls /data/adb/modules 2>/dev/null
echo "--- zygisk present?"
ls /data/adb/zygisksu /data/adb/modules/*zygisk* 2>/dev/null | head

sec "boot timing (the writer runs post-boot; confirm the anchor)"
getprop sys.boot_completed
getprop ro.boot.bootcount
dmesg 2>/dev/null | grep -iE 'defex|vaultkeeper|dmc' | tail -20

sec "done"
PROBE

"${ADB[@]}" push "$TMP" "$DEV" >/dev/null || exit 1
echo "probing $MODEL ..."
"${ADB[@]}" shell "su -c 'sh $DEV'" 2>&1 | tee "$LOG"
"${ADB[@]}" shell "rm -f $DEV" >/dev/null
echo "saved: $LOG"
