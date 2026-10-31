# Getting Odin back without maintenance mode: writing the DMC `at_command` flag

Status quo: `app/src/main/java/df/root/D2Status.java` computes the verdict from the two
vault inputs an app can read (lock-screen credential, maintenance mode) and *assumes*
`at_command = 0`. This document is about the other half: actually setting that byte, on a
device that is rooted after the fact, with no system-app privileges.

## What the flag is

The bootloader consults a 32-byte DMC vault held in a vaultkeeper trustlet in the TEE.
Three bytes matter, in order:

| offset | name | set by |
|---|---|---|
| 0 | `lock` | the lock-screen credential |
| 1 | `maintenance` | Samsung's maintenance mode |
| 2 | `at_command` | the `AT+SUDDLMOD` / `AT+FUS` service escape hatch, cleared again every boot |

Odin is refused (`[1, 0, 0]` -> D2 error) when there is a credential, maintenance mode is
off and nobody authorised the device. Setting byte 2 to 1 is therefore exactly the
behaviour we want: Odin accepted with a password set and maintenance mode off. The vault
is read-modify-write: read the record, refuse anything unexpected, flip byte 2, write it
back, re-read to verify. Never write a record you did not just read.

## The four gates a writer has to pass

1. **Android permission.** The only supported client is
   `com.samsung.android.service.vaultkeeper.VaultKeeperManager`, reached through
   `getInstance("DMC")` and then `read(int)` / `write(int, byte[])`. It is guarded by
   `android.permission.ACCESS_VAULTKEEPER_SERVICE`, `signature|privileged`.
2. **SELinux.** The vaultkeeper service is only reachable from domains the vendor policy
   allows - in practice `system_server` (uid 1000).
3. **The trustlet session.** Namespace `DMC`, 32-byte record, session handling inside the
   manager class; not a plain binder blob we can hand-craft cheaply.
4. **DEFEX.** Samsung's anti-injection enforcement (`task_defex_enforce`,
   `task_defex_user_exec`) blocks attaching to privileged processes. The exploit patches
   it while it runs, but a boot-time writer runs long after, with the patches gone.

## Timing rule that decides the shape of the feature

`DmcService` resets byte 2 during `PHASE_BOOT_COMPLETED`, and the AT authorisation does not
survive a reboot. So a writer is a **per-boot** job: after every boot, wait for
`sys.boot_completed`, then perform the read-modify-verify. It is not a one-time flash.

## Candidate transports

**A. Inject into system_server (what the reference project does).** A Zygisk module's
`postServerSpecialize` lands inside system_server, where uid 1000 and the right SELinux
domain already satisfy gates 1 and 2; from there it calls `getInstance("DMC")` and does the
read-modify-verify. Proven on Galaxy firmware. Costs: it needs Zygisk (under KernelSU that
means ZygiskNext), it is code injection into system_server on a Knox device (gate 4), and
the reference implementation is GPLv3-only.

**B. A root-side harness that runs as the system uid - no injection (try first).**
KernelSU's `su` can run a command as an arbitrary uid. If the permission check resolves the
*calling uid's* grants - which is what `checkPermission` and
`checkCallingOrSelfPermission` do, through `PermissionManagerService` - then a process
running as uid 1000 is checked against the `android` package, which holds
`ACCESS_VAULTKEEPER_SERVICE`, so gate 1 opens without us being privileged or platform
signed. Gate 2 opens with a KernelSU module's `sepolicy.rule`, which can grant our domain
`find` on the vaultkeeper service and a binder channel to it. The process itself can be a
tiny `app_process` (present as `app_process64`) that loads the hidden `VaultKeeperManager`
off the system classpath - `cat /proc/$(pidof system_server)/environ` exposes the exact

**C. Speak to the vendor vaultkeeper HAL / trustlet directly.** Native, no Android
permission at all, and SELinux is again ours to widen with module rules. Highest cost: the
interface (HIDL or AIDL, registered in `vndservicemanager`), the trustlet UUID and its
session protocol all have to be recovered from the device. Only worth it if A and B are both
closed off.

Recommendation: run the probe below, try B, fall back to A (known good but injection), keep
C as the last resort.

## Where this ships

DirtyFrag the app stays what `D2Status.java` says it is: not a root client, because it has
to work on a device that has no root yet. So the writer is **not** an app feature - it is a
separate KernelSU module artifact (`service.sh` waits for boot and does the write,
`sepolicy.rule` covers gate 2, a log lands at `/data/adb/df-download.log`), built and
published next to the APK and flashed by the user from their root manager. If the app ever
offers to install it, that is a deliberate new capability and needs its own decision.

Two safety rules for the module: disabling the module must be the whole uninstall (nothing
persists in the vault beyond a per-boot byte the next boot clears anyway), and the writer
must refuse any record whose first three bytes are not each 0 or 1 - a vault with an
unexpected shape is a vault we do not touch.

## Licensing constraint

This repository carries GPL-2.0-only since upstream `4ec133c`. The BackDownload reference
(`ducthoe/BackDownload`, mirrored at `Eskotek/BackDownload` - itself missing one commit) is
**GPL-3.0-only**, so none of its code may be copied, translated or linked here. It informs
the behaviour and the API names above and nothing more: the transport, the retry loop and
the module scripts have to be written from documented behaviour. Its bundled
`third_party/zygisk.hpp` is the Zygisk API header and carries its own permitting terms - if
candidate A is taken up, read that file's terms rather than assuming the project licence.

## What the probe has to answer

1. Is there a `vaultkeeper` service in `servicemanager`, and which HALs mention vaultkeeper?
2. Which jar holds `com.samsung.android.service.vaultkeeper.VaultKeeperManager`, and is it
   reachable from `app_process` with the system_server classpath?
3. Which package holds `ACCESS_VAULTKEEPER_SERVICE` today, so the grant path is known?
4. Can this manager's `su` really run a command as uid 1000, and what SELinux context does
   that process end up in (`id`, `ps -Z`)?
5. What is `SYSTEMSERVERCLASSPATH` in the running system_server?
6. Which KernelSU version is installed and is Zygisk/ZygiskNext present, in case A is needed?

`tools/d2-probe.sh` pushes the on-device probe, runs it through `su` and saves the log.
Neither script writes to the vault - everything here is a read.

`SYSTEMSERVERCLASSPATH` to use. It fails if the service additionally demands that the
caller really is system_server, for instance by touching
`ActivityThread.currentApplication()` or by checking something only the real service holds.
