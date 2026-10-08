# Changelog

## 1.11

Based on upstream DFRoot 4.1 (upstream 3.0 - 4.1 merged into this fork).

### Engine
- Upstream v4.0 merged: OPPO/OnePlus bypasses, `rmmod` of the OPPO security modules before the
  bootstrap handoff, kprobe cleanup, and the reworked phase markers
- Upstream v4.1 merged: soft reboot now works with every KernelSU derivative. `dfroot.ko` keeps
  its kprobes in static globals and gains a real `module_exit`, so the bootstrap can `rmmod dfroot`
  once late-load is done instead of the module self-unloading by failing its init, and the ksud
  `soft-reboot` is execed in the `u:r:ksu:s0` context only after the late-load process has exited
- The eight embedded kernel modules were rebuilt from v4.1 source, so the shipped modules match
  the marker table the app reads
- The progress bar is strictly linear now: the run bar reaches 100% when the module is in, and
  only then does the verification bar start moving
- Build moved to AGP 9.4.0 with compile/target SDK 37

### DirtyFrag
- Every run log starts with a device banner - manufacturer, model, Android version, security patch
  level and kernel version - so a pasted log can be triaged without asking follow-up questions
- The log header is a plain "SYSTEM" line instead of a firmware build token
- The launcher icon is a vector (adaptive foreground, background and monochrome) instead of five
  PNG densities: the APK is 2.24 MB instead of 2.91 MB
- BakaSU is listed as a manager for non-Samsung devices, with Auto reboot required off there

## 1.10

Based on upstream DFRoot 3.3 (upstream 3.0 - 3.3 merged into this fork).

### Engine
- The exploit is no longer a JNI library: it runs as a staged executable and hands off to a
  bootstrap binary. The bootstrap reads the app's device-protected settings, adopts the zygote
  environment, sets partitions read-only, optionally disables all modules, and only then starts the
  SU daemon
- Runtime kallsyms resolution of `kern_path`, `invalidate_inode_pages2` and `path_put`, which fixes
  namespace violations on some Android 13 kernels
- `__nocfi` annotations on the kernel module - the upstream issue #68 class of crashes on kernels
  with control-flow integrity
- libc++ restore-ordering fix
- `ksud` is staged from the selected SU manager instead of being bundled with the app. The APK is
  2.9 MB instead of 6.5 MB

### DirtyFrag
- Pick your SU manager inside the app; Run stays disabled until one is selected
- KernelSU Modules and soft reboot now work without root
- Autorun keeps its Expert-mode gate and its failed-run interlock
- SU-manager launcher button: a circle while a run is in flight, opening into a "Manager" pill once
  root is verified
- Save the log to Downloads from the circle beside the run pill, available after any finished run
- Neutral grey press highlights throughout, and the Material purple tints are gone - including the
  purple flash for a moment on cold start
- The eight prebuilt kernel modules are committed so that a clone of this repository can build

## 1.08
- KernelSU Modules toggle
- Clearer status text and a refresh when returning to the app

## Earlier
See the release notes on the releases page.
