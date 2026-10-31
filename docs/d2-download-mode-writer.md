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
| 2 | `at_command` | the `AT+SUDDLMOD` / `AT+FUS` service escape hatch, and the only byte DirtyFrag writes; the vendor clears it by itself, measured gone by the second boot |

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

`DmcService` is documented to reset byte 2 during `PHASE_BOOT_COMPLETED`, so the vendor's answer
is that a writer is a **per-boot** job and not a one-time flash. The clear does happen, but not on
the schedule that sentence implies. Measured on an S25 (SM-S931B, patch 2026-10-05):

| when | what the vault answered |
|---|---|
| 18 min into the boot after a write, root restored by hand | `at_command=1`, `state=already-authorized` - nothing needed writing |
| the boot after that, 5 min in, rooted, no write pressed | `at_command=0`, `state=not-authorized` |

So the byte is not durable, and its lifetime is not pinned down well enough to reason from. The
app therefore measures rather than assumes: when a `su` is on the path the pill asks the vault,
and when none is it says Unknown. It used to assume byte 2 was 0 whenever no root was available,
and that assumption is what painted a green dot and an "Allowed, assumed" row on a device whose
vault had just answered `not-authorized`.

The other per-boot fact, and the reason any re-arm hangs off the exploit instead of off boot
completion: measured four minutes into a rebooted S25 there is **no `su` on the path at all**
(`su: inaccessible or not found`). DirtyFrag's root is a page-cache patch and dies with the
reboot; nothing restores it except `ExploitRunner`.

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

## Where this shipped

It went in as an app feature rather than a KernelSU module, which is the opposite of what this
page used to recommend - and the reason is the measurement above: a module's `service.sh` waits
for boot, but on this device there is no root until DirtyFrag's own exploit has run, so a module
would be a script waiting for a root that only the app can produce. The app already owns that
step, so it owns the write too.

* Expert Mode (`df.root.Expert`) arms it, as everything dangerous here. The **Recovery** pill opens
  a card of facts, and under them two OneUI switches in that order - "Recovery Writer" is the byte
  itself, and below it "Autorun Writer" is the want. The second is named for what it does, not for
  when it happens: the automation is what is being switched, not the boot. Both sit on the card
  whether or not Expert Mode is on, dimmed to 40% and labelled "(Expert)" while it is off; the
  switch is disabled, so the flip a row tap asks for is refused at `performClick` rather than
  checked in a second place.
* A second condition binds the same two switches: the firmware has to gate download mode at all,
  which is what `D2Status.read()` answers from the manufacturer and the security patch level. On a
  device that does not, they are labelled "(no gate)" instead of "(Expert)" - "not armed yet" and
  "will never be live here" are not the same thing to come back to. The same reading stops the
  action behind them: `writeDmcFlag` returns without spending an su grant, `refreshRecovery` does
  not ask the harness for a vault that cannot exist on that firmware, and
  `BootReceiver.armD2Vault` logs the skip before it waits for a `su`. A `d2_auto` stored earlier is
  left in prefs rather than silently dropped, because the patch level is a proxy and a setting that
  took an opt-in should not be lost to a proxy that read it the wrong way round.
* One row carries the verdict instead of one row per byte behind it. **DL/Recovery** reads
  "Allowed" or "D2 Blocked" straight from `D2Writer.Vault.gated()` - the bootloader weighs
  `[lock, maintenance, at_command]` and refuses Odin on `[1, 0, 0]` - and "Not gated here" or
  "Unknown" when the vault has not answered. The authorisation byte got no row of its own: the
  writer switch's thumb *is* that byte, on the same card. "Last Check", which printed the harness
  state of the previous attempt, is gone; that word still goes to the log.
* The writer's thumb is the measured state of the byte, not a wish: it is set from what
  `D2Writer.status()` answered, so a write the root manager refused slides back on its own and the
  DL/Recovery row repaints beside it. The card is one fixed 300dp wide - a card cut to its contents
  changed width between a reading that said "Allowed / authorized" and one that said
  "D2 Blocked / cleared", which moved the switch sideways under a finger that was already reaching
  for it.
* Write and clear go through `D2Writer`, the `app_process` harness that runs as uid 1000 in the
  `ksu` domain; nothing is installed and no `sepolicy.rule` exists - `/data/adb/modules` is not
  even a directory on the test device.
* "Autorun Writer" sets one want, honoured on both paths that can honour it. At boot
  `BootReceiver.armD2Vault` performs it after `ExploitRunner` succeeds, having re-read the support
  gate first so a stale want cannot spend an approval nobody is awake to answer. In the foreground
  `MainActivity.autorunAtRoot` performs the same write against a root that is already there - once
  per root, never re-asking a manager that refused. The second path is not decoration: honouring the
  want at boot needs the receiver switched on, the exploit to succeed unattended, and the boot
  broadcast to reach the app at all, and that last one is One UI's decision rather than ours. On the
  S25 the boot log held no `boot:` line from the receiver and no broadcast process start for the
  whole boot, while Samsung's own `BRListParser` was refusing other packages' boot receivers in the
  same minute. A switch that is on and does nothing at boot is worse than one that says where it
  will act, so the row reads "Autorun Writer (at reroot)" when the boot path is off.
* The pill reads the vault whenever a refresh happens with a `su` on the path *and* this firmware
  gates download mode, and a refresh now follows root rather than the process: a foreground watch
  looks every 2 s for su appearing or vanishing - three file stats, no `su` call - and a successful
  exploit run asks immediately. Before that the vault was read once per process start, so an app
  that started on a rebooted phone went on painting the answer it had computed with no root
  available until it was killed and reopened. The verdict row comes strictly from that reading, with
  no fallback state derived from what the app wanted, and the dot is grey rather than a colour the
  estimate guessed at.
* Nothing about a state change is announced at the bottom of the screen. The verdict goes to the run
  log; the card the press came from is still open and already carries the row the write can change,
  so a toast was repetition that covered the next press.
* A write nobody pressed for is logged like a write that was. The foreground autorun puts its attempt
  line in the run log before the `su` leaves, so a refused or hung grant still has a line above its
  absence, and the same verdict wording a press prints once the vault answers. Until that was fixed the
  switch wrote silently: the pill said Allowed and only logcat knew a byte had appeared.

Two safety rules carried over from the module design: nothing persists beyond a byte the vendor
clears by itself, so disabling the feature is the whole uninstall; and the harness refuses any
record whose first three bytes are not each 0 or 1 - a vault with an unexpected shape is a vault
we do not touch.

## Not proven end to end

The write works: byte 2 flips to 1, verification re-reads it, and the record is otherwise
untouched. What has not been watched on a real device is the consequence - booting the patched
firmware into Odin and seeing it accepted rather than the D2 error. That is now demonstrable on the
test S25: a credential is set there, the vault answers `lock=1, maintenance=0`, and the bootloader
refuses Odin on exactly that pair while byte 2 is 0 - which is the red "D2 Blocked" the card shows.
An earlier note on this page said the test device carried no credential and so could not engage the
gate; that was written before it did.

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
