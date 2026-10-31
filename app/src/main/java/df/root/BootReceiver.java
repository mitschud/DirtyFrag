package df.root;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.PowerManager;
import android.util.Log;

import java.io.File;

/**
 * Auto-root on boot. Safety rules learned in the field:
 *  - A failed run disables the receiver; the user re-enables it in the app.
 *  - Soft reboot at boot only ever happens when the user explicitly opted in
 *    on the Autorun card (same as pre-3.2 behaviour).
 *
 * Since upstream 3.2 the exploit binary no longer takes a soft-reboot flag:
 * the LKM execs "bootstrap", which reads soft_reboot / su_manager /
 * disable_modules directly out of the device-encrypted prefs at
 * /data/user_de/0/df.root/shared_prefs/dfroot.xml. BootReceiver therefore
 * mirrors the user's choice into that key before starting the run.
 */
public class BootReceiver extends BroadcastReceiver implements IReporter {
    private static final String TAG = "dfroot";

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (new File("/dev/df").exists()) {
            Log.i(TAG, "boot: already hooked, skipping");
            return;
        }
        Log.i(TAG, "boot: " + intent.getAction());
        final Context deCtx = context.createDeviceProtectedStorageContext();
        boolean expert = deCtx.getSharedPreferences("dfroot", Context.MODE_PRIVATE)
                .getBoolean("expert_mode", false);
        if (!expert) {
            Log.i(TAG, "boot: expert mode off - autorun skipped");
            return;
        }
        boolean autoSoftReboot = deCtx.getSharedPreferences("dfroot", Context.MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", false);
        // auto_soft_reboot=true: on success, ksud triggers its OWN soft reboot
        // after late-load completes - so Zygisk/LSPosed modules (which need a
        // fresh Zygote with the module loaded) become active in the same power
        // session. With it off, the exploit still roots the device but nothing
        // reboots. bootstrap reads this from the pref, not from argv.
        deCtx.getSharedPreferences("dfroot", Context.MODE_PRIVATE)
                .edit().putBoolean("soft_reboot", autoSoftReboot).apply();

        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "dfroot:boot");
        wl.acquire();
        new Thread(() -> {
            boolean ok = false;
            try {
                int rc = ExploitRunner.run(deCtx, this);
                Log.i(TAG, "boot: exploit rc=" + rc);
                ok = rc == 0;
            } catch (Exception e) {
                Log.e(TAG, "boot: exploit exception", e);
            } finally {
                wl.release();
            }
            // The download-mode byte is per boot, and the only thing that can write it is the su
            // this run just put back, so re-arming belongs here and nowhere earlier.
            if (ok) armD2Vault(deCtx);
            if (!ok) {
                Log.i(TAG, "boot: failed - disabling autorun interlock");
                context.getPackageManager().setComponentEnabledSetting(
                        new ComponentName(context, BootReceiver.class),
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        PackageManager.DONT_KILL_APP);
            }
        }, "dfroot-boot").start();
    }

    /**
     * Re-arm the vault's download-mode byte, for owners who opted in with the "Autorun Writer"
     * row of the recovery card (d2_auto in this same device-protected prefs file, written by
     * MainActivity.PREF_D2_AUTO).
     *
     * <p>Both halves of this are per boot, which is why the automation exists. The vendor clears
     * the byte at the end of every boot, and DirtyFrag's root is a page-cache patch that a reboot
     * erases - four minutes into a rebooted S25 there is no su anywhere on the path at all, so a
     * boot-time writer that ran before ExploitRunner would simply have nothing to write with.
     *
     * <p>The vault is read before it is written: on a device where the byte is already what the
     * owner wants this costs one round trip, and a boot that cannot reach the vault (no su, the
     * service refused) is logged and left alone rather than hammered - a TEE does not become
     * cooperative by asking it twice in a row, and this runs unattended.
     */
    private void armD2Vault(Context ctx) {
        SharedPreferences sp = ctx.getSharedPreferences("dfroot", Context.MODE_PRIVATE);
        if (!sp.getBoolean("d2_auto", false)) return;
        // The switch that sets this flag is inert on firmware that never gates download mode, but
        // the flag outlives that reading: it is the one setting in this prefs file meant to survive
        // a reboot, and the security patch that decides support is only a proxy for the firmware
        // generation. So the gate is checked here as well, not trusted from the UI - this runs
        // unattended, and the alternative is an su prompt nobody is awake to answer on a device
        // that has no vaultkeeper service to answer it to.
        if (!D2Status.read(ctx).supported) {
            Log.i(TAG, "boot: d2 re-arm skipped - this firmware does not gate download mode");
            return;
        }
        try {
            // This run started ksud; give it a moment to bind su into the path before asking.
            for (int i = 0; i < 10 && !D2Writer.suPresent(); i++) Thread.sleep(3000L);
            D2Writer.Vault v = D2Writer.status(ctx);
            if (!v.ok) {
                Log.i(TAG, "boot: d2 re-arm skipped, vault unreadable: " + v.state);
                return;
            }
            if (v.atCommand == 1) {
                Log.i(TAG, "boot: d2 already authorised, nothing to write");
                return;
            }
            v = D2Writer.authorize(ctx);
            Log.i(TAG, "boot: d2 re-arm " + v.state
                    + (v.ok ? " at_command=" + v.atCommand : " - " + v.detail));
        } catch (Exception e) {
            Log.e(TAG, "boot: d2 re-arm threw", e);
        }
    }
}