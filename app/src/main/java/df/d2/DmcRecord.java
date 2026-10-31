package df.d2;

/**
 * The DMC policy record the Samsung bootloader consults before it accepts Odin.
 *
 * <p>It is a 32-byte blob kept in a vaultkeeper trustlet in the TEE. Only the first three
 * bytes are ours to interpret; the remaining 29 belong to the vendor and are opaque to us.
 * The bootloader refuses download mode when a lock-screen credential exists, maintenance
 * mode is off and nobody authorised the device - the same triple the D2 error prints.
 *
 * <p>Rule that keeps this safe: a record is only ever modified after it has just been read
 * back, and only when its three flag bytes look like plain flags. An unexpected shape is a
 * vault we do not touch - writing a fabricated record into a TEE is not something a second
 * boot can undo.
 */
public final class DmcRecord {

    public static final int SIZE = 32;

    /** Set from the lock-screen credential. */
    public static final int LOCK = 0;
    /** Set by Samsung's maintenance mode. */
    public static final int MAINTENANCE = 1;
    /** The AT-command authorisation the service escape hatch sets; cleared every boot. */
    public static final int AT_COMMAND = 2;

    private DmcRecord() {
    }

    /**
     * True when we recognise the record: exact length, and each flag byte is 0 or 1 rather
     * than some value this firmware never produces.
     */
    public static boolean wellFormed(byte[] record) {
        if (record == null || record.length != SIZE) {
            return false;
        }
        for (int offset = 0; offset <= AT_COMMAND; offset++) {
            if (record[offset] != 0 && record[offset] != 1) {
                return false;
            }
        }
        return true;
    }

    public static int flag(byte[] record, int offset) {
        return record[offset];
    }

    public static boolean authorized(byte[] record) {
        return record != null && record.length > AT_COMMAND && record[AT_COMMAND] == 1;
    }

    /**
     * A copy of {@code record} with the authorisation byte set. Everything else - including
     * the 29 opaque bytes and the current lock/maintenance flags - is carried over verbatim.
     */
    public static byte[] authorize(byte[] record) {
        byte[] next = record.clone();
        next[AT_COMMAND] = 1;
        return next;
    }

    /**
     * The same copy with the authorisation byte cleared, for undoing an authorisation before
     * the next boot would have done it anyway. Note this is not a restore: the byte came from
     * a service tool or from us, and clearing it only ever moves the device back towards the
     * state every boot starts in.
     */
    public static byte[] clear(byte[] record) {
        byte[] next = record.clone();
        next[AT_COMMAND] = 0;
        return next;
    }

    public static String hex(byte[] record) {
        if (record == null) {
            return "-";
        }
        StringBuilder out = new StringBuilder(record.length * 2);
        for (byte b : record) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16));
            out.append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }
}
