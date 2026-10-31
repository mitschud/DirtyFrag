package df.root;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.TimeUnit;

/**
 * Asks the vendor's own vaultkeeper service what the DMC vault says, and on request changes
 * its download-mode authorisation byte - from the phone, with the owner's root grant, and
 * without injecting anything into system_server.
 *
 * <p>The vault lives in a trustlet in the TEE and the only supported way into it is
 * {@code com.samsung.android.service.vaultkeeper.VaultKeeperManager}, a class on
 * system_server's classpath behind a signature|privileged permission. So the work happens in
 * a helper process, and the helper is this very APK: {@code app_process} is pointed at
 * {@code base.apk}, which puts framework.jar - and with it VaultKeeperManager - on its boot
 * classpath, while the harness in df.d2 drives the manager reflectively.
 *
 * <p>Two gates the plain "just run it as root" approach fails:
 * <ul>
 *   <li><b>name</b> - the service resolves the calling pid to a process name through libvkjni's
 *       nativeGetProcessName, which opens {@code /proc/<pid>/cmdline}, and only accepts
 *       "system_server" for a process ActivityManager does not know. A name can only be chosen
 *       at execve time, so df-d2-launch - staged out of this APK's native lib dir, exactly as
 *       ksud and bootstrap are by ExploitRunner - execve's app_process64 with argv[0] set.
 *       Android's sh cannot do this (no "exec -a"), and no ART call can do it afterwards.</li>
 *   <li><b>uid</b> - the service checks the calling uid's grants, and root has none for
 *       ACCESS_VAULTKEEPER_SERVICE on this firmware. uid 1000 is the platform package, which
 *       does, so the harness drops to that uid itself.</li>
 * </ul>
 *
 * <p>Measured on a Galaxy S25 (SM-S931B): uid 1000, in the root manager's own SELinux domain,
 * named system_server, the read answers with the 32-byte record - no sepolicy rule and no
 * injection anywhere.
 *
 * <p>What this does not pretend: DirtyFrag is still not a root client where it matters.
 * Nothing here needs a rooted device - with no su binary the pill falls back to the
 * public-API reading in {@link D2Status}. Whether the owner granted su is only knowable by
 * asking, so a refused su is its own reported state instead of a guess.
 */
final class D2Writer {

    /** Shipped as a .so because AGP only packages lib*.so; staged by stage() below. */
    private static final String LIB = "libdf-d2-launch.so";
    private static final String STAGED = "df-d2-launch";
    /** The uid whose package holds ACCESS_VAULTKEEPER_SERVICE. */
    private static final int SYSTEM_UID = 1000;

    /** Where a su binary has been seen; KernelSU binds its own into /system/bin. */
    private static final String[] SU_PATHS = {"/system/bin/su", "/system/xbin/su", "/sbin/su"};

    /** A hung su, not a slow TEE: the round trip itself is far under a second. */
    private static final long READ_TIMEOUT_S = 20L;
    private static final long WRITE_TIMEOUT_S = 40L;

    /** What the vault said, or why we could not ask. */
    static final class Vault {
        /** True when a DFD2 verdict came back, so the three bytes below are the vault's. */
        final boolean ok;
        /** The harness state: authorized, written, cleared, read-failed, ... */
        final String state;
        /** Byte 2 of the record - the authorisation. -1 when unknown. */
        final int atCommand;
        /** Bytes 0 and 1: the lock-screen credential and maintenance mode. -1 unknown. */
        final int lock, maintenance;
        /** Everything the helper printed, for the run log and the submenu's last row. */
        final String detail;

        Vault(boolean ok, String state, int atCommand, int lock, int maintenance, String detail) {
            this.ok = ok;
            this.state = state;
            this.atCommand = atCommand;
            this.lock = lock;
            this.maintenance = maintenance;
            this.detail = detail;
        }

        /** True once the vault says this device is authorised for download mode. */
        boolean authorized() {
            return ok && atCommand == 1;
        }

        /**
         * What the bootloader will answer a download-mode request with: it refuses Odin on
         * [lock=1, maintenance=0, at_command=0], which is the D2 error.
         */
        boolean gated() {
            return ok && lock == 1 && maintenance == 0 && atCommand == 0;
        }

        /** Short enough for one submenu row. */
        String label() {
            if (!ok) return "Unknown (" + state + ")";
            return atCommand == 1 ? "Authorised" : "Not authorised";
        }
    }

    private D2Writer() {}

    /**
     * Whether some su binary is present. This does not mean DirtyFrag may use it - only the
     * root manager knows, and it only says so by answering or refusing an actual call.
     */
    static boolean suPresent() {
        return suPath() != null;
    }

    static Vault status(Context ctx) {
        return run(ctx, "status");
    }

    static Vault authorize(Context ctx) {
        return run(ctx, "authorize");
    }

    static Vault clear(Context ctx) {
        return run(ctx, "clear");
    }

    private static String suPath() {
        for (String path : SU_PATHS) {
            if (new File(path).canExecute()) return path;
        }
        return null;
    }

    /**
     * Runs the helper through su and turns its DFD2 line into a Vault. The command is built
     * from paths this app owns plus one fixed mode word, so no stray space or quote can turn
     * into an argument.
     */
    private static Vault run(Context ctx, String mode) {
        String su = suPath();
        if (su == null) {
            return new Vault(false, "no-su", -1, -1, -1,
                    "no su binary on this device, so the vault cannot be read at all");
        }

        File staged;
        try {
            staged = stage(ctx);
        } catch (IOException e) {
            // Fall back to the copy the installer already put in the native lib dir; only give
            // up when that one is not runnable either.
            staged = new File(ctx.getApplicationInfo().nativeLibraryDir, LIB);
            if (!staged.canExecute()) {
                return new Vault(false, "stage-failed", -1, -1, -1, e + " (and " + staged + ")");
            }
        }

        long timeout = "status".equals(mode) ? READ_TIMEOUT_S : WRITE_TIMEOUT_S;
        String apk = ctx.getApplicationInfo().sourceDir;
        String command = staged.getAbsolutePath() + " " + apk + " " + mode + " " + SYSTEM_UID;
        StringBuilder out = new StringBuilder();
        Process p = null;
        try {
            // One stream: su's own complaint and the harness's verdict then cannot arrive out
            // of order and fill a pipe nobody is draining.
            ProcessBuilder pb = new ProcessBuilder(su, "-c", command).redirectErrorStream(true);
            p = pb.start();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    out.append(line).append('\n');
                }
            }
            if (!p.waitFor(timeout, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return new Vault(false, "timeout", -1, -1, -1, clip(out)
                        + "\nsu did not answer within " + timeout
                        + "s - approve the superuser request, then try again");
            }
        } catch (IOException | InterruptedException e) {
            if (p != null) p.destroyForcibly();
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            return new Vault(false, "su-failed", -1, -1, -1, clip(out) + "\n" + e);
        }

        Vault parsed = parse(out.toString());
        // su answered without the harness ever running: nearly always a refused grant.
        return parsed.ok ? parsed : new Vault(false, parsed.state, -1, -1, -1, clip(out));
    }

    /**
     * Reads the verdict out of the harness's machine-readable line rather than out of prose, so
     * a firmware that reworded its service cannot break what the app makes of it.
     */
    private static Vault parse(String output) {
        for (String line : output.split("\n")) {
            if (!line.startsWith("DFD2 ")) continue;
            String state = "";
            int at = -1, lock = -1, maint = -1;
            for (String token : line.split(" ")) {
                int eq = token.indexOf('=');
                if (eq < 0) continue;
                String key = token.substring(0, eq);
                String value = token.substring(eq + 1);
                try {
                    if (key.equals("state")) state = value;
                    else if (key.equals("at_command")) at = Integer.parseInt(value);
                    else if (key.equals("lock")) lock = Integer.parseInt(value);
                    else if (key.equals("maintenance")) maint = Integer.parseInt(value);
                } catch (NumberFormatException ignored) {
                    // A byte this firmware will not explain stays -1: unknown, never guessed.
                }
            }
            if (!state.isEmpty()) return new Vault(true, state, at, lock, maint, output.trim());
        }
        String trimmed = output.trim();
        String first = trimmed.isEmpty() ? "" : trimmed.split("\n")[0];
        return new Vault(false, first.isEmpty() ? "su-silent" : clip(first), -1, -1, -1, output);
    }

    /**
     * Copies the launcher next to the app's other staged binaries, the way ExploitRunner
     * stages ksud and bootstrap: the path handed to su is then one this app owns, so an update
     * refreshes it instead of waiting on a reinstall. The app data dir is noexec for the app,
     * but this one is exec'd by root, where that restriction does not apply.
     */
    private static File stage(Context ctx) throws IOException {
        File src = new File(ctx.getApplicationInfo().nativeLibraryDir, LIB);
        if (!src.exists()) throw new IOException(src + " is not installed with this APK");
        File dest = new File(ctx.getFilesDir().getParentFile(), STAGED);
        Files.copy(src.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
        if (!dest.setExecutable(true, false)) {
            throw new IOException("setExecutable failed: " + dest.getAbsolutePath());
        }
        return dest;
    }

    /** Details are for a human reading a log, so they are kept short and flat. */
    private static String clip(Object s) {
        if (s == null) return "";
        String t = s.toString().trim();
        return t.length() <= 400 ? t : t.substring(0, 400) + " ...";
    }
}
