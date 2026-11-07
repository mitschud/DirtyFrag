package df.root;

import java.io.File;

/**
 * What this boot's /dev/df node says, and - more importantly for the UI - what it does not say.
 *
 * <p>The node is created by the hook shellcode itself. {@code libcxx.S} runs
 * {@code openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL|O_CLOEXEC, 0)} as a one-shot mutex, its own
 * comment reading "To avoid later call of hook to execute payload, create file as mutex": the
 * payload runs on the first successful create and returns without running on every later hit.
 * Nothing in {@code jni/} or {@code lkm/} unlinks it, and {@code /dev} is root-owned, so the app can
 * neither delete the node nor take that lock a second time.
 *
 * <p>Two consequences the rest of the app has to live with:
 * <ul>
 *   <li>The node proves the payload <em>started</em>. It is not evidence that root <em>arrived</em>:
 *       downstream of it the chain still has to load the module, exec bootstrap, start ksud and bind
 *       su, and every one of those can fail - bootstrap's own dfme0/dfme1/dfme2 error nodes all sit
 *       after this one. Treating the node as "rooted" is what let a half-finished run describe
 *       itself as rooted.</li>
 *   <li>While the node exists a second run cannot work. {@code patch_hook} finds libc++ "already
 *       patched" and returns 0, the orphan re-triggers the hook, the mutex swallows the payload, and
 *       exp.c polls to its timeout. Same-boot retry is out of reach by design, not by our choice -
 *       so a Run button that invites it is a trap rather than a convenience.</li>
 * </ul>
 */
final class RootState {

    /** The mutex node the shellcode wins. Exists from the hook until reboot (devtmpfs). */
    static final String HOOK_NODE = "/dev/df";

    enum State {
        /** Nothing has hooked this boot, so a run can still work. */
        NOT_HOOKED,
        /** The payload ran and a su binary is present where KernelSU binds it. */
        ROOTED,
        /**
         * The payload ran and no su binary is present anywhere: the chain stopped somewhere after
         * the mutex and before the SU daemon. Deliberately not called "failed" - a manager that binds
         * su outside {@code D2Writer.SU_PATHS} would look like this while being perfectly rooted, and
         * the advice we give (reboot, do not retry) is correct in both readings, so the wording has
         * to claim nothing beyond "no su here".
         */
        HOOKED_NO_ROOT
    }

    private RootState() {}

    /** True from the moment the shellcode wins its mutex until the device reboots. */
    static boolean hooked() {
        return new File(HOOK_NODE).exists();
    }

    /** The three-way reading of this boot that the Run pill and the status bar are built from. */
    static State state() {
        if (!hooked()) return State.NOT_HOOKED;
        // The same probe startRootWatch already runs every tick, so "rooted" means one thing in
        // this app rather than two. Presence is not permission - D2Writer is explicit that only the
        // manager answers that by answering or refusing - but it is the only reading available to an
        // unprivileged app, and it is the reading the root watch already acts on.
        return D2Writer.suPresent() ? State.ROOTED : State.HOOKED_NO_ROOT;
    }
}
