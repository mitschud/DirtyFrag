package df.d2;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Process identity, printed once so a failed run says which uid and domain it ran in. */
public final class Diagnostics {

    private Diagnostics() {
    }

    public static String identity() {
        return "context=" + context() + " uid=" + uid();
    }

    /** The SELinux domain of this process - the gate that decides binder access to the vault. */
    public static String context() {
        try {
            return new String(Files.readAllBytes(Paths.get("/proc/self/attr/current")),
                    StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return "?";
        }
    }

    public static int uid() {
        try {
            String status = new String(Files.readAllBytes(Paths.get("/proc/self/status")),
                    StandardCharsets.UTF_8);
            for (String line : status.split("\n")) {
                if (line.startsWith("Uid:")) {
                    return Integer.parseInt(line.trim().split("\\s+")[1]);
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        return -1;
    }

    /**
     * The two names a caller check can read: the kernel task name (comm) and the command line.
     * Printed together so it is visible which one an option actually moved.
     */
    public static String selfName() {
        return "comm=" + read("/proc/self/comm") + " cmdline=" + read("/proc/self/cmdline");
    }

    private static String read(String path) {
        try {
            return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8)
                    .replace('\0', ' ')
                    .trim();
        } catch (Exception e) {
            return "?";
        }
    }

    public static void report(String line) {
        System.out.println(line);
    }

    /** One exception line, unwrapping the reflection layer so the real reason is visible. */
    public static void complain(Throwable t) {
        Throwable cursor = t;
        if (cursor instanceof InvocationTargetException) {
            cursor = cursor.getCause();
        }
        System.err.println(cursor.getClass().getName() + ": " + cursor.getMessage());
    }
}
