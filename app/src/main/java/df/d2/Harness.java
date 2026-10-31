package df.d2;

import java.lang.reflect.Method;

/**
 * Reads - and on request authorises or clears - the DMC vault that gates download mode
 * (Odin) on Samsung firmware.
 *
 * <p>The class is compiled into the DirtyFrag APK and also built as a standalone jar for adb.
 * Either way it runs as a plain {@code app_process} started by df-d2-launch, because that is
 * what puts {@code framework.jar} on the boot classpath - which is where the vendor's own
 * {@code VaultKeeperManager} lives in this firmware. We drive that class rather than speaking
 * binder to {@code VaultKeeperService} directly, because the real interface is
 * {@code read(String,int,int[])} / {@code write(String,int,byte[],byte[])} and the manager
 * fills in those extra arguments for reasons we would rather not guess at.
 *
 * <p>Modes: {@code status} is read-only; {@code authorize} and {@code clear} each perform
 * exactly one read-modify-verify of byte 2. Every mode prints a single {@code DFD2 ...} line
 * so a caller can parse the verdict without scraping prose.
 *
 * <pre>
 *   df-d2-launch &lt;apk-or-jar&gt; status 1000
 *   df-d2-launch &lt;apk-or-jar&gt; authorize 1000
 *   df-d2-launch &lt;apk-or-jar&gt; clear 1000
 * </pre>
 *
 * <p>The launcher, not any option here, is what makes the vendor service answer at all: it
 * execve's app_process64 with argv[0] "system_server", the name the service reads out of
 * {@code /proc/<pid>/cmdline} when it checks who is calling. This ART offers no way to change
 * a running process's command line, and Android's sh has no "exec -a".
 */
public final class Harness {

    /** The trustlet namespace that holds the download-mode policy record. */
    static final String VAULT = "DMC";
    /**
     * The vault slot holding the record. This firmware declares {@code TYPE_VAULT_DATA_MIN},
     * {@code TYPE_VAULT_DATA_UNSHELTERED} and {@code TYPE_NONCE} all as 1, so the value is
     * unambiguous even though three names share it.
     */
    static final int SLOT = 1;

    static final int EXIT_OK = 0;
    static final int EXIT_READ_FAILED = 1;
    static final int EXIT_UNSUPPORTED = 2;
    static final int EXIT_WRITE_FAILED = 3;
    static final int EXIT_VERIFY_FAILED = 4;
    static final int EXIT_UNAVAILABLE = 5;

    private static final String MANAGER =
            "com.samsung.android.service.vaultkeeper.VaultKeeperManager";

    public static void main(String[] args) {
        String mode = "status";
        int uid = 0;
        for (int i = 0; i < args.length; i++) {
            if ("--uid".equals(args[i]) && i + 1 < args.length) {
                uid = Integer.parseInt(args[++i]);
            } else if (!args[i].startsWith("--")) {
                mode = args[i];
            }
        }

        adoptUid(uid);
        Diagnostics.report(Diagnostics.identity());
        Diagnostics.report(Diagnostics.selfName());
        try {
            System.exit(run(mode));
        } catch (ClassNotFoundException e) {
            Diagnostics.report("DFD2 state=class-missing class=" + MANAGER);
            Diagnostics.complain(e);
            System.exit(EXIT_UNAVAILABLE);
        } catch (Throwable t) {
            Diagnostics.report("DFD2 state=error");
            Diagnostics.complain(t);
            System.exit(EXIT_UNAVAILABLE);
        }
    }

    /**
     * The vaultkeeper service checks the calling uid against the platform's own grants. Root
     * has no grant for ACCESS_VAULTKEEPER_SERVICE (this vendor's check does not honour the
     * AOSP root bypass), but uid 1000 - the {@code android} package, which declares the
     * permission - does. So the harness drops to that uid before it touches the vault, the
     * way the doc's Transport B predicted, and stays in whatever SELinux domain launched it.
     *
     * <p>The other half of the service's gate - the caller's name - is set by our launcher,
     * which execs app_process64 with argv[0] "system_server"; this ART offers no way to change
     * the command line from inside a running process (VMRuntime only has setProcessPackageName).
     */
    private static void adoptUid(int uid) {
        if (uid <= 0) {
            return;
        }
        try {
            // Reached reflectively so this build needs nothing but a JDK: android.system.Os is
            // already on the boot classpath of the app_process we run inside.
            Class<?> os = Class.forName("android.system.Os");
            os.getMethod("setgid", int.class).invoke(null, uid);
            os.getMethod("setuid", int.class).invoke(null, uid);
        } catch (Throwable t) {
            Diagnostics.report("DFD2 state=uid-failed want=" + uid);
            Diagnostics.complain(t);
            System.exit(EXIT_UNAVAILABLE);
        }
    }

    /**
     * {@code status} only reads. {@code authorize} and {@code clear} each do exactly one
     * read-modify-verify of the authorisation byte, and only ever write back a copy of the
     * record that was read a moment earlier.
     */
    private static int run(String mode) throws Exception {
        final boolean authorize = "authorize".equals(mode);
        final boolean writing = authorize || "clear".equals(mode);
        /* What byte 2 has to end up as; only meaningful while writing. */
        final int want = authorize ? 1 : 0;

        Class<?> manager = Class.forName(MANAGER);
        Method getInstance = manager.getMethod("getInstance", String.class);
        Method read = manager.getMethod("read", int.class);
        Method write = manager.getMethod("write", int.class, byte[].class);
        Method errorCode = manager.getMethod("getErrorCode");

        Object vault = getInstance.invoke(null, VAULT);
        if (vault == null) {
            Diagnostics.report("DFD2 state=no-vault vault=" + VAULT);
            return EXIT_UNAVAILABLE;
        }

        byte[] record = (byte[]) read.invoke(vault, SLOT);
        if (record == null) {
            Diagnostics.report("DFD2 state=read-failed vault=" + VAULT + " slot=" + SLOT
                    + " err=" + errorCode.invoke(vault));
            return EXIT_READ_FAILED;
        }
        if (!DmcRecord.wellFormed(record)) {
            // A vault of a shape we do not understand: report it, never write it.
            Diagnostics.report("DFD2 state=unsupported size=" + record.length
                    + " flags=" + DmcRecord.hex(prefix(record))
                    + " record=" + DmcRecord.hex(record));
            return EXIT_UNSUPPORTED;
        }

        int lock = DmcRecord.flag(record, DmcRecord.LOCK);
        int maintenance = DmcRecord.flag(record, DmcRecord.MAINTENANCE);
        int atCommand = DmcRecord.flag(record, DmcRecord.AT_COMMAND);

        if (!writing) {
            Diagnostics.report(line(atCommand == 1 ? "authorized" : "not-authorized",
                    lock, maintenance, atCommand, record, errorOf(vault, errorCode)));
            return EXIT_OK;
        }
        if (atCommand == want) {
            Diagnostics.report(line(authorize ? "already-authorized" : "already-cleared",
                    lock, maintenance, atCommand, record, errorOf(vault, errorCode)));
            return EXIT_OK;
        }

        // Only the authorisation byte changes. The opaque tail and the other two flags go back
        // exactly as they were read.
        int code = number(write.invoke(vault, SLOT,
                authorize ? DmcRecord.authorize(record) : DmcRecord.clear(record)));
        if (code != 0) {
            // The manager has its own failure vocabulary (SUCCESS = 0); never retry blind.
            Diagnostics.report(line("write-failed", lock, maintenance, atCommand, record, code));
            return EXIT_WRITE_FAILED;
        }

        byte[] after = (byte[]) read.invoke(vault, SLOT);
        int at = after == null || after.length <= DmcRecord.AT_COMMAND ? -1
                : DmcRecord.flag(after, DmcRecord.AT_COMMAND);
        if (at != want) {
            // Lock and maintenance may legitimately move while we look away; only the byte we
            // asked for has to stick.
            Diagnostics.report(line("verify-failed", lock, maintenance, at,
                    after == null ? record : after, errorOf(vault, errorCode)));
            return EXIT_VERIFY_FAILED;
        }
        Diagnostics.report(line(authorize ? "written" : "cleared",
                DmcRecord.flag(after, DmcRecord.LOCK),
                DmcRecord.flag(after, DmcRecord.MAINTENANCE), at, after,
                errorOf(vault, errorCode)));
        return EXIT_OK;
    }

    private static String line(String state, int lock, int maintenance, int atCommand,
                               byte[] record, int error) {
        return "DFD2 state=" + state + " lock=" + lock + " maintenance=" + maintenance
                + " at_command=" + atCommand + " err=" + error
                + " record=" + DmcRecord.hex(record);
    }

    private static byte[] prefix(byte[] record) {
        byte[] out = new byte[Math.min(DmcRecord.AT_COMMAND + 1, record.length)];
        System.arraycopy(record, 0, out, 0, out.length);
        return out;
    }

    private static int errorOf(Object vault, Method errorCode) throws Exception {
        return number(errorCode.invoke(vault));
    }

    private static int number(Object value) {
        return value instanceof Number ? ((Number) value).intValue() : Integer.MIN_VALUE;
    }
}