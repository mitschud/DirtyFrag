# DirtyFrag (CVE-2026-43284)

DirtyFrag is a hardened fork of [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot). It exploits
CVE-2026-43284 (DirtyFrag), a kernel page cache write primitive, to load a kernel module without an
unlocked bootloader and without a custom kernel. The fork targets Samsung phones (OneUI, RKP and KDP
hardening) and keeps upstream's SU-manager agnostic design.

> [!IMPORTANT]
> Root is **ephemeral**. The kernel module, `su` and any loaded modules are gone the moment the
> device reboots. A reboot always returns the phone to a clean, unrooted state - which is also the
> recovery path if a run goes wrong.

## Install

1. Install the DirtyFrag APK from [Releases](https://github.com/mitschud/DirtyFrag/releases/latest).
2. Install an SU manager that **ships `libksud.so`**:
   - Samsung - **required**:
     - [diabl0w's KernelSU](https://github.com/diabl0w/KernelSU/releases/tag/samsung-v1.0)
     - [zandatsu07's KernelSU-Next](https://github.com/zandatsu07/KernelSU-Next/releases/latest) (Working only on S23 and below Kernel 5.15)
   - Other:
     - [KernelSU](https://github.com/tiann/KernelSU/releases/latest)
     - [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest)
     - [KowSU](https://github.com/KOWX712/KernelSU/releases/latest)
     - [BakaSU](https://github.com/Baka-SU/BakaSU/releases/latest) (formerly ReSukiSU)
3. Open DirtyFrag, pick your manager in the **SU Manager** card, then press **Run exploit**.

> [!WARNING]
> Since 1.10 (upstream 3.2) DirtyFrag no longer bundles `ksud` - it is staged from the selected
> manager's own `libksud.so`. A manager that does not ship that library cannot give you root. The
> older advice to install a CI / Actions build of the manager no longer applies.

A fresh install of DirtyFrag gets a new Android UID, so the grant in the manager has to be given
again after every reinstall.

<img width="540" height="1170" alt="Screenshot_20261007_224642" src="https://github.com/user-attachments/assets/b12c72e3-05de-44d1-ad9f-251672370d8b" />

## Features

- Choose your SU manager inside the app
- **Autorun** (start on boot), gated behind Expert mode, with a failed-run interlock that disables
  itself after a failed attempt so a bad run cannot boot-loop you
- **Auto reboot** (soft reboot) - since 1.11 (upstream 4.1) this works with every KernelSU
  derivative: `dfroot.ko` is unloaded after late-load and ksud's own `soft-reboot` is run
- **KernelSU Modules** on/off - works without root, applied by the kernel module before ksud starts
- RO Partition Protection
- Advanced log, with one tap to save it to Downloads
- Update pill in the title, so you can see when a newer release is published
- Shizuku not needed

## FAQ

**Q: Log says patching failed and that my device isn't vulnerable**

A: Sorry, there is no fix. Either:
  - your device's kernel is too new
  - your device manufacturer backported the official mitigation
  - [accidental mitigation](https://github.com/V4bel/dirtyfrag/issues/23#issuecomment-4405314290)
    (typically seen on kernel 6.1)

**Q: Log says "SUCCESS" or "ksud exited with error", but I don't have root**

A: Turn off **Auto reboot** on the Autorun card if it is enabled - a soft reboot that the manager
cannot complete leaves the loaded module unloaded again. Otherwise see
[upstream discussion 69](https://github.com/diabl0w/DFRoot/discussions/69).

**Q: I installed a module and now I can't launch root without crashing**

A: Set the **KernelSU Modules** card to Disabled and reroot. The switch works without root, which is
the point - it is the escape hatch when a module is the thing that is crashing the run.

**Q: Module + Autorun and now I am bootlooping**

A: Android usually detects the bootloop and offers Safe Mode; otherwise hold **Volume Down** during
boot. From Safe Mode turn Autorun off and set KernelSU Modules to Disabled, or just uninstall
DirtyFrag until you stabilise. If you cannot get far enough into the system, `adb uninstall df.root`
from any PC works on user builds without root.

**Q: The progress bar sits at 0 percent**

A: That is the app's log-marker mapping, not the exploit. The run window is 70 seconds - do not
re-run a "slow" run, the daemon may still be working.

**Q: How do I remove root cleanly?**

A: Use the in-app **Remove KSU/KSUD** entry. Never run `ksud uninstall` by hand alongside DirtyFrag:
it tries to restore a boot image backup that this flow never made, and can reboot the device.

## Building

```sh
JAVA_HOME="<Android Studio jbr>" ./gradlew assembleRelease
```

The APK is written to `app/build/outputs/apk/release/dirtyfrag.apk`.

Release builds are signed with `app/keystore.jks`, which is gitignored (the signing config expects
alias `dirtyfrag` and `dirtyfrag` for both passwords). Generate your own before building:

```sh
keytool -genkeypair -v -keystore app/keystore.jks -alias dirtyfrag \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass dirtyfrag -keypass dirtyfrag
```

The eight prebuilt kernel modules are committed under `app/src/main/jni/ko/`. Upstream gitignores
them and builds them per-KMI in CI; this fork commits them so a plain clone builds without a DDK
toolchain. They are built by this repo's `Build` workflow (the `LKMs / <kmi>` jobs) from the
current `lkm/dfroot.c`, so they must be rebuilt whenever that file changes: run the workflow,
download the `df-lkm-<kmi>` artifacts and drop them in this directory. To build them yourself
instead, use upstream's `make` / podman DDK flow.

## How it works

The Android kernel decrypts AES-CBC ESP packets directly into the page cache of files open for
`splice()`. By crafting `IV = AES_ECB_DEC(key, current_content) XOR desired_content`, any
16-byte-aligned block in a mapped shared library can be overwritten without write permission and
without copy-on-write.

The exploit uses this primitive to patch shellcode into `libc++.so` in the kernel's page cache. The
next privileged call to the hooked function runs the shellcode, which loads the kernel module via
`insmod`.

### Exploit chain

1. **IpSec transform** - the app allocates a `UdpEncapsulationSocket` plus an SPI and builds an
   AES-CBC/HMAC-SHA256 ESP transform through `IpSecManager`.
2. **splicehelper -> crash_dump64** - splicehelper is spliced into `crash_dump64` using the CBC
   primitive. `crash_dump64` runs in the `crash_dump` SELinux domain, which can open `vendor_file`
   labelled files that `untrusted_app` cannot read - the bridge we need.
3. **dfroot.ko -> vendor_file** - the kernel module is written through that bridge into a
   `vendor_file`-labelled file.
4. **libc++ hook** (fires in init, uid=0, tid=1) - shellcode patched at
   `std::ostream::sentry::sentry()`. It checks uid and tid, creates `/dev/df` as a one-shot mutex so
   it cannot re-enter, then execs `insmod` in the `vendor_modprobe` domain.
5. **dfroot.ko init** - sets SELinux permissive, bypasses DEFEX via kprobes where present, then uses
   `call_usermodehelper` to run the bootstrap.
6. **bootstrap** - reads the app's device-protected settings, adopts the zygote environment, sets
   partitions read-only, optionally disables all modules, and finally launches the SU daemon from
   your installed SU manager.

## Credits

- Upstream project and exploit chain: https://github.com/diabl0w/DFRoot
- Original PoC and various code: https://github.com/lsposed/lspromise
- SELinux permissive kernel modules and various code: https://github.com/polygraphene/DFReroot
- Unprivileged XFRM socket method: https://github.com/combeng6th/DirtyInit
