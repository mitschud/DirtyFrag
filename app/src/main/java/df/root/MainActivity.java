package df.root;

import android.app.Activity;
import android.content.Context;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.util.Log;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends Activity implements IReporter {

    private static final String TAG = "dfroot";

    private ActivityMainBinding binding;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private final StringBuilder logBuffer = new StringBuilder();
    private File lastLogFile;
    private boolean running;
    private boolean runArmed;
    private boolean advancedLog;
    private boolean expertMode;
    private String exploitPhase = "";
    private int cleanupSteps;
    private float seg1;
    private float pillPercent = 0.48f;
    /** SU-manager launcher geometry: a 54dp circle with a 12dp gap to the Run
     *  pill while a run is in flight; once root is verified the circle morphs
     *  into a pill as wide as the shrunken Run pill (setCompactButton +
     *  morphKsuToPill). Matches the share circle's 54dp on the left. */
    private static final float KSU_CIRCLE_DP = 54f;
    private static final float KSU_GAP_DP = 12f;
    /** The Run pill's left inset: what the 26% vertical guideline used to say. */
    private static final float PILL_INSET_FRACTION = 0.26f;
    private android.animation.ValueAnimator ksuMorph;
    private android.animation.ValueAnimator updateMorph;
    private TextView titleView;
    /** The headline's width in px, taken from the toolbar's own title paint - the
     *  only paint that knows how wide "DirtyFrag" renders, and therefore how wide
     *  the update pill has to be to cover it. See showUpdatePill. */
    private int headlinePx;
    /** The last public-API reading, kept for the pill's submenu. Null until first read. */
    private D2Status.Result mOdin;
    /** The last DMC vault reading, taken through su when that was possible. Null until the
     *  vault has been read once; d2Prefs() keeps it across restarts. See D2Writer. */
    private D2Writer.Vault mVault;
    /** Whether a su binary was on the path the last time the root watch looked. The watch exists
     *  because both halves of the download-mode answer die with a reboot, and the owner restores
     *  one of them by hand from this screen. See startRootWatch. */
    private boolean mSuWasPresent;
    /** The watch itself, null while the app is in the background. See startRootWatch. */
    private Runnable mRootWatch;
    /** True once the Autorun Writer's write has been attempted against the current root, so a
     *  refused or unanswered su stays a state rather than becoming a loop - the rule the switch
     *  on the card already follows for a press. Cleared when su leaves the path. Written from the
     *  executor that reads the vault and cleared from the main thread that watches for root, so
     *  it is volatile rather than a race that happens to work. */
    private volatile boolean mAutorunTried;
    /** How often the root watch looks. The look is three file stats, not an su call. */
    private static final long ROOT_WATCH_MS = 2000L;
    private boolean moduleRefresh;

    /** Device-protected storage context: bootstrap.c reads its prefs from
     *  /data/user_de/0/df.root/, so every pref the exploit depends on must live
     *  there, not in credential-protected storage. */
    private Context mDeCtx;
    /** Package name of the SU manager whose libksud.so gets staged, or null. */
    private String suManagerPkg;
    private CharSequence suManagerLabel;
    /** A failed run locks the Run button until reboot (page-cache patch). */
    private boolean failedRun;
    /** Raw "***FAILED***: ..." text from the exploit, used for the failure log. */
    private String lastFailReason;

    // ---- Movable card stack (VIS1 - VIS5) -----------------------------------

    /** The card keys as they are written to dfroot_ui, in the shipped order.
     *  "sumanager" is first and is the one card that can never be hidden. */
    private static final String[] CARD_KEYS = {"sumanager", "autorun", "modules", "log"};
    /** Hide button per card, index-parallel to CARD_KEYS. They live in the root
     *  layout, not inside the cards: MaterialCardView clips its children to the
     *  rounded outline, and the badge has to straddle the card's top-left edge. */
    private final android.widget.ImageButton[] hideButtons =
            new android.widget.ImageButton[CARD_KEYS.length];
    /** Cards the user hid; kept in sync with the prefs so a restart is faithful. */
    private final List<String> hiddenCards = new ArrayList<>();
    /** True while a drag has the scrollable log blacked out (VIS2.1). */
    private boolean logHiddenForDrag;
    /** True while the log is allowed on screen at all: the advanced-log switch
     *  is on, there is a run to show and the advanced-log card is not collapsed.
     *  Composed with {@link #logHiddenForDrag} into one fade (VIS2.1/VIS4). */
    private boolean logAllowed;
    /** How long the log and its gradient take to ease in or away. */
    private static final long LOG_FADE_MS = 180L;
    /** Hide button geometry: a 30dp badge sitting on the card's top edge. */
    private static final float HIDE_BTN_DP = 30f;
    /** Invisible full-screen sheet that turns the next tap into "accept this
     *  layout" while a card is still outlined. It has to be a real view: the
     *  log scroll and the pills eat their own touches, so a listener on the
     *  root layout would never hear the tap. */
    private View acceptOverlay;

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        mMain.post(() -> {
            // Drive the two-step progress bar from the raw (unfiltered) lines.
            for (String line : msg.split("\n", -1)) {
                driveProgress(line.trim());
            }
            for (String line : msg.split("\n", -1)) {
                String t = line.trim();
                // Skip empty lines to keep the log compact.
                if (t.isEmpty()) {
                    continue;
                }
                // Drop byte-progress counters ("0 ?", "512 ?", ...).
                if (t.matches("\\d+\\s*(\\u2026|\\.{3})?")) {
                    continue;
                }
                // Drop internal patch/hook details and raw result markers: the
                // app renders its own SETUP/EXPLOIT/INIT/CLEANUP headers and
                // synthesizes a single failure line instead of the raw one.
                if (t.contains("hook=") || t.equals("ksud start: SUCCESS")
                        || t.contains("ERROR - ")) {
                    continue;
                }
                // Strip hex file offsets: ".../libc.so+0x6e8b0" -> ".../libc.so"
                t = t.replaceAll("\\+0x[0-9a-fA-F]+$", "");
                t = stripHeader(t);
                appendLog(t);
            }
            binding.outputScroll.post(() -> binding.outputScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void appendLog(String line) {
        binding.outputView.append(styleLogLine(line));
        binding.outputView.append("\n");
        logBuffer.append(line).append('\n');
        saveLog();
    }

    /** Translates raw native log lines into two-step progress-bar states.
     *  STRICTLY LINEAR: seg 1 (the exploit run) climbs to 100% and only then does seg 2
     *  (verification) start climbing. The two bars never move at the same time.
     *  Seg 1 tracks setup + file patching + the hook firing; seg 2 tracks the bootstrap,
     *  which reports progress by touching /dev/dfm* nodes that exp.c polls for 70 seconds. */
    private void driveProgress(String t) {
        if (t.isEmpty()) return;
        // v4.0 marker table: a failure is reported as "<stage>: ERROR - <reason>".
        int err = t.indexOf("ERROR - ");
        if (err >= 0) {
            lastFailReason = t.substring(err + "ERROR - ".length()).trim();
        }
        switch (t) {
            case "=== setup ===":
                exploitPhase = "setup";
                setSeg1(0.05f);
                break;
            case "=== exploit (patching files) ===":
                exploitPhase = "exploit";
                setSeg1(0.15f);
                break;
            case "=== init  ===":
                // The run bar is nearly done; the verification bar stays EMPTY until the
                // module is actually in and the exploit bar has read 100%.
                exploitPhase = "init";
                setSeg1(0.98f);
                break;
            case "=== cleanup ===":
                exploitPhase = "cleanup";
                cleanupSteps = 0;
                break;
            default:
                break;
        }
        if (exploitPhase.equals("setup") && t.startsWith("found ko_target:")) {
            setSeg1(0.10f);
        }
        if (exploitPhase.equals("exploit")) {
            if (t.startsWith("patch: crash_dump64")) {
                setSeg1(0.30f);
            } else if (t.contains("<- dfroot.ko")) {
                setSeg1(0.50f);
            } else if (t.startsWith("Finding symbol offsets")) {
                setSeg1(0.60f);
            } else if (t.contains("<- shellcode")) {
                setSeg1(0.75f);
            } else if (t.contains("<- trampoline")) {
                setSeg1(0.90f);
            } else if (t.startsWith("Triggering hook")) {
                setSeg1(0.95f);
            }
        }
        // Run bar finishes here - the module is in, nothing left to patch.
        if (t.startsWith("libc++: loading custom module")) {
            setSeg1(1f);
        }
        // Verification bar: one step per bootstrap marker (see exp.c markers[]).
        // v4.0 renamed every marker and dropped the "env adopted" / "partitions set
        // ro" confirmations, so these steps are re-keyed to the new table.
        if (t.startsWith("kernel module: launching bootstrap")) {
            setSeg2(0.14f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: loading app preferences file")) {
            setSeg2(0.28f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: cloning zygote env")
                || t.startsWith("bootstrap: WARNING - clone zygote env failed")) {
            setSeg2(0.42f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: setting partitions ro")
                || t.startsWith("bootstrap: WARNING - set partitions ro failed")) {
            setSeg2(0.57f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: disabling ksu modules")) {
            setSeg2(0.71f, "Verification", 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: starting SU daemon")) {
            setSeg2(0.85f, "Verification", 0xFFFFFFFF);
        }
        if (t.equals("ksud start: SUCCESS")) {
            setSeg1(1f);
            setSeg2(1f, "Verified", 0xFFFFFFFF);
        }
        if (exploitPhase.equals("cleanup") && t.startsWith("restoring")) {
            cleanupSteps++;
        }
    }

    private void setSeg1(float p) {
        seg1 = p;
        binding.twoStep.setSeg1(p, Math.round(p * 100) + "%");
    }

    private void setSeg2(float p, String label, int color) {
        binding.twoStep.setSeg2(p, label, color);
    }

    /** VIS4: the room the stack keeps under the advanced-log card, which is also
     *  exactly how tall the log panel and its fade are - one number in
     *  @dimen/log_window_height, so the window and the box can never disagree. */
    private int logWindowPx() {
        return getResources().getDimensionPixelSize(R.dimen.log_window_height);
    }

    /** Turn the advanced log on or off from anywhere - the switch, a card being
     *  lifted, the saved setting at startup.
     *  OneUiSwitch is drawn from scratch and only reports a change when a finger
     *  clicks it: quietly calling setChecked() moves the thumb and tells nobody,
     *  which left the pill showing off while the log went on behaving as if it
     *  were still on. Everything therefore comes through here. */
    private void setAdvancedLog(boolean on) {
        advancedLog = on;
        binding.switchAdvancedLog.setChecked(on);
        createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("advanced_log", on).apply();
        updateLogVisibility();
    }

    /** Visibility of log / share button / progress bar, composed from the
     *  advanced-log setting and whether any run data exists. The log block
     *  needs the switch; the share circle does not - a finished run can always
     *  be saved. */
    private void updateLogVisibility() {
        boolean hasRun = logBuffer.length() > 0
                || (lastLogFile != null && lastLogFile.exists());
        // The log lives under its own card, so a collapsed card takes the log
        // with it - "Reset UI Layout" brings both back.
        logAllowed = advancedLog && hasRun && !hiddenCards.contains("log");
        // VIS4: the log hangs off the advanced-log card, so the window the stack
        // keeps for it follows the log. The stack then does the placing - the
        // panel and its fade are handed over in setupCardStack().
        // The window is cut before the log fades up, so the panel and its
        // gradient are already lying in the right place when they appear: show
        // the log first and slide the gradient in behind it, and the log reads
        // as one bright flash before the fade catches up with it.
        // The window exists for exactly as long as the log is on screen and for
        // no longer - a drag included. Lifting a card puts the log away
        // (VIS2.1), and the room it kept has to go with it: held open, every
        // card below the one being moved sat a whole window too low and slid
        // that much further than it ever should, which is what made a reorder
        // look like the cards underneath were dropping out of the screen. The
        // stack re-lays itself out the moment the window changes, so the drag
        // that is starting measures the slots the cards actually have.
        binding.cardStack.setLogGap(logAllowed ? logWindowPx() : 0);
        fadeLog(logAllowed && !logHiddenForDrag);
        // Share circle: any FINISHED run, advanced log on or off. Still hidden
        // while a run is in flight (the log is being written) and shown for a
        // saved log from a previous boot, which is finished by definition.
        setShareButtonVisible(hasRun && !running);
        // Progress bar is the simple status: always visible.
    }

    /**
     * Ease the log box in or away (VIS2.1, VIS4). The log has half a dozen
     * reasons to appear or vanish - the switch, a run starting, a card being
     * lifted, that card being collapsed - and every one of them used to flip the
     * views between GONE and VISIBLE like a light switch, which read as a flash.
     * It now moves on one alpha, and a log that is fading out only leaves the
     * layout once there is nothing left of it to see.
     * One alpha for one box: the text and the gradient over it are the same view
     * since VIS4, so there is nothing left that could fall a frame behind.
     */
    private void fadeLog(boolean show) {
        final View box = binding.logWindow;
        boolean visible = box.getVisibility() == View.VISIBLE;
        float target = show ? 1f : 0f;
        if (visible == show && box.getAlpha() == target) return;
        box.animate().cancel();
        if (show) box.setVisibility(View.VISIBLE);
        box.animate().alpha(target).setDuration(LOG_FADE_MS)
                .withEndAction(() -> {
                    if (box.getAlpha() <= 0f) box.setVisibility(View.GONE);
                })
                .start();
    }

    /** Pop the share circle in/out with the same animation the KernelSU
     *  launcher circle uses (fade + 0.6x -> 1x scale, 150ms delay). */
    private void setShareButtonVisible(boolean show) {
        android.widget.ImageButton b = binding.btnShareLog;
        boolean wasVisible = b.getVisibility() == View.VISIBLE
                && b.getAlpha() > 0.99f;
        if (show && !wasVisible) {
            b.setVisibility(View.VISIBLE);
            b.setAlpha(0f);
            b.setScaleX(0.6f);
            b.setScaleY(0.6f);
            b.postDelayed(() -> b.animate()
                    .alpha(1f).scaleX(1f).scaleY(1f).setDuration(180).start(), 150);
        } else if (show) {
            b.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(120).start();
        } else if (wasVisible) {
            b.animate().alpha(0f).scaleX(0.6f).scaleY(0.6f).setDuration(200)
                    .withEndAction(() -> b.setVisibility(View.GONE)).start();
        }
    }

    /** "=== setup ===" -> "SETUP"; "=== exploit (patching files) ===" ->
     *  "PATCHING"; "=== exploit failed: x ===" -> "EXPLOIT FAILED: X". */
    private static String stripHeader(String t) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^===\\s*(.*?)\\s*===$").matcher(t);
        if (!m.matches()) return t;
        String h = m.group(1).toUpperCase();
        // The native binary still prints "=== exploit (patching files) ===";
        // the UI shows the short form.
        if (h.equals("EXPLOIT (PATCHING FILES)")) return "PATCHING";
        return h;
    }

    /** The log's first line. Deliberately generic: the device banner that
     *  ExploitRunner prints immediately below it already carries manufacturer,
     *  model, Android version, patch level and kernel version, so the old
     *  model-prefixed firmware token ("S931BXXU1AYB2") was redundant noise. */
    private static final String LOG_HEADER = "SYSTEM";

    /** Header lines render big, white and bold; the rest is dimmed. */
    private boolean isHeader(String line) {
        return line.equals("SETUP") || line.equals("PATCHING")
                || line.equals("EXPLOIT (PATCHING FILES)")
                || line.equals("INIT") || line.equals("CLEANUP")
                || line.startsWith("EXPLOIT FAILED")
                || line.equals(LOG_HEADER);
    }

    /** Header lines render big, white and bold; the rest is dimmed. */
    private CharSequence styleLogLine(String line) {
        SpannableString ss = new SpannableString(line);
        if (isHeader(line)) {
            ss.setSpan(new StyleSpan(Typeface.BOLD), 0, line.length(), 0);
            ss.setSpan(new RelativeSizeSpan(1.3f), 0, line.length(), 0);
            ss.setSpan(new ForegroundColorSpan(0xFFFFFFFF), 0, line.length(), 0);
        } else {
            ss.setSpan(new ForegroundColorSpan(0xFFB3B3B3), 0, line.length(), 0);
        }
        return ss;
    }

    private void saveLog() {
        try (FileOutputStream out = new FileOutputStream(lastLogFile)) {
            out.write(logBuffer.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (IOException ignored) {
        }
        // Remember which boot this log came from - it is invalidated on reboot.
        createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putInt("log_boot_count", bootCount()).apply();
    }

    private int bootCount() {
        try {
            return android.provider.Settings.Global.getInt(getContentResolver(),
                    android.provider.Settings.Global.BOOT_COUNT, -1);
        } catch (Exception e) {
            return -1;
        }
    }

    private String readLastLog() {
        if (lastLogFile == null || !lastLogFile.exists()) return "";
        try (java.io.FileInputStream in = new java.io.FileInputStream(lastLogFile);
             java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) != -1; ) bos.write(buf, 0, n);
            String log = bos.toString(java.nio.charset.StandardCharsets.UTF_8.name()).trim();
            // Normalize exploit-result headers to lowercase (older runs saved
            // them uppercase); the file gets rewritten on next save.
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("(===\\s*exploit\\s+(?:success|failed[^=]*)\\s*===)",
                            java.util.regex.Pattern.CASE_INSENSITIVE)
                    .matcher(log);
            // The StringBuilder overloads of appendReplacement/appendTail only exist
            // from API 34 on, and minSdk is 32, so this normaliser used to die with
            // NoSuchMethodError on anything older than Android 14. StringBuffer has
            // carried both overloads since the first API level.
            StringBuffer sb = new StringBuffer();
            while (m.find()) m.appendReplacement(sb, java.util.regex.Matcher
                    .quoteReplacement(m.group().toLowerCase()));
            m.appendTail(sb);
            return sb.toString();
        } catch (IOException e) {
            return "";
        }
    }

    /**
     * Screen zoom and Font size are locked for the duration of the activity:
     * the pill, toolbar and card geometry were all measured at one screen
     * width in dp and stop agreeing with each other as soon as it moves. See
     * {@link ScaleFix} for why the anchor is a width and not a dpi value.
     */
    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(ScaleFix.wrap(newBase));
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mDeCtx = createDeviceProtectedStorageContext();
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        // The pill's 26%/48% box is arithmetic, not a RelativeLayout rule (see
        // applyRunPillGeometry), so it has to be put in place before the first
        // measure - otherwise the first frame shows it at wrap_content width.
        applyRunPillGeometry(0f);

        // The header is the app's name and nothing else. The version number that
        // used to ride next to it is still recorded, just not in the one line of
        // chrome the user has to look past to reach the cards: on every start here,
        // and in the run log as "app version: ..." (ExploitRunner). What takes the
        // headline instead is the update pill, but only once the check below has
        // something to say - see showUpdatePill.
        Log.i(TAG, "version " + BuildConfig.VERSION_NAME);
        // NOTE: no setSupportActionBar() - it makes the ActionBar delegate draw
        // the title and ignore the toolbar's titleTextAppearance (breaks bold).
        // The framework Toolbar renders its own title via android:titleTextAppearance.

        // Update check (SamSU-style): when GitHub has a newer release, the headline
        // is covered by a lime pill reading "Update" and tapping that pill opens the
        // releases page. No newer release, no pill - the header stays the plain word.
        binding.updatePill.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            openUrl("https://github.com/mitschud/DirtyFrag/releases");
        });
        mExec.execute(this::checkForAppUpdate);

        // Recovery / download mode: the pill left of the menu button. Pressing it opens the card
        // of facts behind the dot - the verdict the bootloader will reach for a download-mode
        // request, and the readings that verdict is built from. The two settings that touch the
        // byte live inside that card as OneUI switches: inert until Expert Mode is on in the
        // overflow menu, and inert on firmware that never gates download mode at all. Pressing
        // the pill can therefore never reach Samsung's vault by accident. D2Writer says how the
        // write is done; D2Status is the rootless reading the dot and the device row fall back on
        // when there is no su grant to ask.
        android.view.View.OnClickListener openRecovery = v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            showRecoveryPopup();
        };
        binding.odinPill.setOnClickListener(openRecovery);
        binding.odinPill.setOnLongClickListener(v -> {
            openRecovery.onClick(v);
            return true;
        });
        mExec.execute(this::refreshRecovery);

        // SU Manager card: upstream 3.2 deleted the bundled assets/ksud, so the
        // exploit stages libksud.so out of the chosen manager's
        // nativeLibraryDir and refuses to run without one. Only apps that
        // actually ship that library are offered.
        loadSuManagerPref();
        binding.rowSuManager.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            showSuManagerPopup();
        });

        // KSU modules toggle: since 3.2 this is a plain preference, not a root
        // operation. bootstrap.c reads disable_modules and touches a `disable`
        // flag file in every installed module before ksud runs, so the toggle
        // works before the device is rooted and applies on the next root.
        moduleRefresh = true;
        binding.switchModules.setChecked(!mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("disable_modules", false));
        moduleRefresh = false;
        binding.modulesSubtitle.setText(binding.switchModules.isChecked()
                ? "Enabled - Active at next reroot"
                : "Disabled - No Modules on reroot");
        binding.switchModules.setOnCheckedChangeListener((btn, on) -> {
            if (moduleRefresh) return;
            btn.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            applyModuleState(on);
        });

        // Force real bold (wght 700) One UI Sans on the toolbar title TextView -
        // and on the two pill labels, whose textStyle="bold" alone renders lighter
        // than the title's explicit wght 700 next to them.
        binding.toolbar.post(() -> {
            Typeface base = null;
            try {
                // ResourcesCompat went away with the rest of androidx; Resources.getFont
                // is the framework call and does the same job for a res/font entry.
                base = getResources().getFont(R.font.inter_vf);
            } catch (RuntimeException notAFont) {
                // leave base null and fall through to the check below
            }
            if (base == null) return;
            Typeface bold = Typeface.create(base, 700, false);
            binding.odinLabel.setTypeface(bold);
            binding.updateLabel.setTypeface(bold);
            for (int i = 0; i < binding.toolbar.getChildCount(); i++) {
                View child = binding.toolbar.getChildAt(i);
                if (child instanceof TextView) {
                    titleView = (TextView) child;
                    titleView.setTypeface(bold);
                    // Measured with the title's own paint, after its own typeface has
                    // been set, because that is the combination the headline renders
                    // in - and the update pill has to be exactly this wide to cover it.
                    headlinePx = Math.round(
                            titleView.getPaint().measureText("DirtyFrag"));
                }
            }
        });

        if (new File("/dev/df").exists()) {
            setRootedState();
        }

        // Show the log from the last run, if any. No run yet -> log hidden.
        // A log saved before the current boot is stale: delete it so a reboot
        // always starts with a clean screen (log + share icon hidden).
        lastLogFile = new File(createDeviceProtectedStorageContext().getFilesDir(), "last_run.log");
        int savedBoot = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE).getInt("log_boot_count", -1);
        if (lastLogFile.exists() && savedBoot != bootCount()) {
            lastLogFile.delete();
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", false).apply();
        }
        String last = readLastLog();
        boolean hasLastLog = !last.isEmpty();
        if (hasLastLog) {
            appendLog(LOG_HEADER);
            for (String l : last.split("\n")) {
                String t = stripHeader(l.trim());
                // Skip stale headers, old result lines and duplicate header lines.
                if (t.isEmpty()
                        || t.equals("LAST RUN")
                        || t.equals("EXPLOIT SUCCESS")
                        || t.equals(LOG_HEADER)) {
                    continue;
                }
                appendLog(t);
            }
        }

        // Advanced log toggle: full log vs. simple status (progress bar only).
        advancedLog = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("advanced_log", false);
        binding.switchAdvancedLog.setChecked(advancedLog);
        binding.switchAdvancedLog.setOnCheckedChangeListener(
                (btn, checked) -> setAdvancedLog(checked));
        updateLogVisibility();

        // Restore the simple status for the current state: rooted device or a
        // successful last run -> 100% + Verified; failed run -> Failed.
        boolean rootedNow = new File("/dev/df").exists();
        boolean lastSuccess = hasLastLog
                && createDeviceProtectedStorageContext()
                        .getSharedPreferences("dfroot", MODE_PRIVATE)
                        .getBoolean("last_run_success", false);
        boolean lastFailed = hasLastLog
                && last.toLowerCase().contains("=== exploit failed");
        if (rootedNow || lastSuccess) {
            binding.twoStep.setSeg1(1f, "100%");
            binding.twoStep.setSeg2(1f, "Verified", 0xFFFFFFFF);
        } else if (lastFailed) {
            setFailedState();
        }

        binding.btnRun.setOnClickListener(v -> {
            if (running) return;
            // Two-tap confirmation: first tap arms ("Are you sure"), second runs.
            if (!runArmed) {
                runArmed = true;
                v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                binding.btnRun.setText("Are you sure");
                return;
            }
            runArmed = false;
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            running = true;
            binding.btnRun.setEnabled(false);
            binding.btnRun.setText("Running");
            // Same dark greyed-out styling as the Rooted state.
            binding.btnRun.setTextColor(0xFF6E6E6E);
            binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
            binding.btnRun.setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
            binding.outputView.setText("");
            logBuffer.setLength(0);
            if (lastLogFile.exists()) lastLogFile.delete();
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", false).apply();
            appendLog(LOG_HEADER);
            binding.twoStep.reset();
            setCompactButton(true, false);
            updateLogVisibility();
            mExec.execute(this::runExploit);
        });

        binding.btnKsu.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            openKsu();
        });

        // Subtle push-in + keyboard-tap haptic on the run button.
        binding.btnRun.setOnTouchListener((v, ev) -> {
            switch (ev.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                    v.animate().scaleX(0.96f).scaleY(0.96f).setDuration(80).start();
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    v.animate().scaleX(1f).scaleY(1f).setDuration(120).start();
                    break;
                default:
                    break;
            }
            return false;
        });

        binding.btnShareLog.setOnClickListener(v -> shareLog());

        // Overflow menu on the custom grey-circle button: the popup closes
        // ONLY on outside taps, so multi-tap actions are possible.
        binding.btnMenu.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            float md = getResources().getDisplayMetrics().density;
            boolean rootedMenu = new File("/dev/df").exists();
            final android.widget.PopupWindow[] pwRef = {null};

            android.widget.LinearLayout box = new android.widget.LinearLayout(this);
            box.setOrientation(android.widget.LinearLayout.VERTICAL);
            box.setBackgroundResource(R.drawable.popup_bg);
            box.setPadding(0, (int) (6 * md), 0, (int) (6 * md));

            // -- Open Github Page row --
            TextView ghRow = new TextView(this);
            ghRow.setBackgroundResource(R.drawable.menu_row_highlight);
            ghRow.setText("Open Github Page");
            ghRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            ghRow.setPadding((int) (20 * md), 0, 0, 0);
            ghRow.setTextColor(0xFFE8E8E8);
            ghRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            ghRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                openUrl("https://github.com/mitschud/DirtyFrag");
            });
            box.addView(ghRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Reset UI Layout row (VIS5): this slot used to hold "Remove
            //    KSU/KSUD", which never did anything useful. It now puts the
            //    cards back in the shipped order and brings back every card the
            //    user hid.
            //
            //    Second row rather than third, and named for what it resets: the menu reads
            //    action, action, state now, and a two-word label gives back the width that the
            //    Expert row's switch reserves, so the menu is not a wide grey band with one short
            //    word in it. --
            TextView rlRow = new TextView(this);
            rlRow.setBackgroundResource(R.drawable.menu_row_highlight);
            rlRow.setText("Reset UI Layout");
            rlRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            rlRow.setPadding((int) (20 * md), 0, 0, 0);
            rlRow.setTextColor(0xFFE8E8E8);
            rlRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            rlRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                if (pwRef[0] != null) pwRef[0].dismiss();
                resetCardLayout();
            });
            box.addView(rlRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Expert Mode row: the same OneUI switch the recovery card uses --
            // A dot that comes and goes says what is true; a switch says what is true and is also
            // the thing that changes it, which is what a row that arms every dangerous setting
            // here ought to be. The label takes the row's remaining width and the row stays the
            // touch target by routing the tap to the switch, so the flag flips in one place - the
            // same shape as odinToggleRow, not a second copy of the click logic to fall out of step.
            //
            // Last of the three rows and not in the middle of them: the two above are actions that
            // close the menu when fired, this one is a state that does not, and a switch sitting
            // between two actions reads like a third thing to fire. It is also the row that decides
            // whether the writer switches on the recovery card can be moved at all, so it belongs
            // at the bottom - closest to the card it arms.
            android.widget.LinearLayout exRow = new android.widget.LinearLayout(this);
            exRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            exRow.setPadding((int) (20 * md), 0, (int) (20 * md), 0);
            exRow.setBackgroundResource(R.drawable.menu_row_highlight);
            TextView exText = new TextView(this);
            exText.setText("Expert Mode");
            exText.setTextColor(0xFFE8E8E8);
            exText.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            exRow.addView(exText, new android.widget.LinearLayout.LayoutParams(
                    0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            OneUiSwitch exSwitch = new OneUiSwitch(this);
            // A state being displayed, not one changed under a finger: a menu that opens with the
            // thumb sliding in is the view claiming a finger moved it before there was one.
            exSwitch.setCheckedQuiet(expertMode);
            exRow.addView(exSwitch, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                    android.view.ViewGroup.LayoutParams.WRAP_CONTENT));
            exSwitch.setOnCheckedChangeListener((view, checked) -> {
                expertMode = checked;
                createDeviceProtectedStorageContext()
                        .getSharedPreferences("dfroot", MODE_PRIVATE)
                        .edit().putBoolean("expert_mode", expertMode).apply();
                applyExpertMode();
            });
            exRow.setOnClickListener(v2 -> exSwitch.performClick());
            box.addView(exRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // Centered separators between the rows: after row 1 and after row 2, the Expert row
            // being the third of them.
            android.widget.LinearLayout.LayoutParams sepLp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sepLp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            android.view.View sep1 = new android.view.View(this);
            sep1.setBackgroundColor(0xFF3F3F3F);
            box.addView(sep1, 1, sepLp);
            android.view.View sep2 = new android.view.View(this);
            sep2.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep2Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep2Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep2, 3, sep2Lp);

            // Width: content, but at least 190dp so the popup reads properly. Measured with every
            // row in, since the longest label is the one that decides it - and the switch row now
            // carries a label of its own instead of a dot.
            box.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
            int pw_w = Math.max(box.getMeasuredWidth(), (int) (190 * md));
            pwRef[0] = showToolbarCard(box, pw_w, md);
        });
        ComponentName bootReceiver = new ComponentName(this, BootReceiver.class);
        int state = getPackageManager().getComponentEnabledSetting(bootReceiver);
        boolean bootEnabled = state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
        binding.switchBootStart.setChecked(bootEnabled);
        binding.switchBootStart.setOnCheckedChangeListener((btn, checked) -> {
            getPackageManager().setComponentEnabledSetting(bootReceiver,
                checked ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            binding.switchAutoSoftReboot.setEnabled(checked);
        });

        boolean autoSoftReboot = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", false);
        binding.switchAutoSoftReboot.setChecked(autoSoftReboot);
        binding.switchAutoSoftReboot.setEnabled(bootEnabled);
        binding.switchAutoSoftReboot.setOnCheckedChangeListener((btn, checked) ->
            createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("auto_soft_reboot", checked).apply());

        // Expert mode gates the autorun card: locked until toggled in the menu.
        expertMode = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("expert_mode", false);
        applyExpertMode();

        // Movable card stack (VIS1 - VIS5): hold-to-lift reorder with the card
        // stuck to the finger, the per-card hide badge and the order + hidden
        // flags from dfroot_ui.
        setupCardStack();

        // Run stays locked until an SU manager is selected (and, after a failed
        // run, until the device has been rebooted).
        updateRunButton();
    }

    /** Expert mode off: the autorun card is inaccessible - greyed text and
     *  disabled toggles, titles suffixed with (Expert). */
    private void applyExpertMode() {
        boolean ok = expertMode;
        binding.tvAutorunTitle.setText(ok ? "Autorun" : "Autorun (Expert)");
        binding.tvRebootTitle.setText(ok ? "Auto reboot" : "Auto reboot (Expert)");
        binding.tvAutorunTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvAutorunDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.tvRebootTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvRebootDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.switchBootStart.setEnabled(ok);
        binding.switchAutoSoftReboot.setEnabled(ok
                && binding.switchBootStart.isChecked());
    }

    // ---- Movable card stack (VIS1 - VIS5) -----------------------------------

    /** The stack card a prefs key refers to. */
    private DraggableCardView cardForKey(String key) {
        if (key == null) return null;
        switch (key) {
            case "sumanager": return binding.cardSuManager;
            case "autorun": return binding.cardBoot;
            case "modules": return binding.cardModules;
            case "log": return binding.cardLog;
            default: return null;
        }
    }

    /** The prefs key of a stack card, or null if it is not one of them. */
    private String keyForCard(View card) {
        for (String key : CARD_KEYS) {
            if (cardForKey(key) == card) return key;
        }
        return null;
    }

    /**
     * Wires the movable stack (VIS1): the hide badges, the order and hidden
     * flags the user left behind on last exit, and the tap-outside-to-accept
     * gesture. Nothing here changes what a card DOES - the toggles, the manager
     * picker and the autorun component are wired where they always were, only
     * the position of their card in the stack moves (RULES 4).
     */
    private void setupCardStack() {
        final CardStackLayout stack = binding.cardStack;
        // Above the log scroll and the pills (0dp), below the accept sheet
        // (5dp) and the hide badges (26dp): the stack keeps first pick of every
        // touch, the sheet catches the rest, the badge floats over both.
        stack.setElevation(10 * getResources().getDisplayMetrics().density);
        // VIS4: the log panel belongs to the advanced-log card. The stack keeps a
        // window of room under that card for the log to show through and slides
        // the panel and its fade into it - the stack owns the geometry, so a
        // settle, a collapse or a reorder can never leave the log somewhere else.
        stack.setLogCard(binding.cardLog);
        stack.setLogWindow(binding.logWindow);
        stack.setLogGap(logAllowed ? logWindowPx() : 0);
        stack.setListener(new CardStackLayout.Listener() {
            @Override
            public void onCardLifted(View card) {
                // VIS4: the log belongs to a card, and lifting that card means it
                // may end up somewhere else - with the log trailing after it.
                // Chasing the window across a stack in motion is what kept
                // leaving the panel and its gradient a layout behind, so picking
                // a card up now puts the advanced log away. The thumb flips off
                // while the card is still in the hand, and the log is turned back
                // on once the card is where it belongs.
                if (advancedLog) setAdvancedLog(false);
                setLogHiddenForDrag(true);
                setAcceptOverlay(false);
                showHideButton(card);
                // Closing the window takes the cards under the log card - this one
                // included - straight back up again, and the card then snaps down
                // under the finger. Keep the chip glued through both of those
                // rather than leaving it where the card was before the layout
                // moved it; onCardMoved takes over from the next drag frame.
                followBadgeDuringSettle(card);
            }

            @Override
            public void onCardMoved(View card) {
                placeHideButton(card);
            }

            @Override
            public void onCardDropped(View card, boolean moved) {
                setLogHiddenForDrag(false);
                setAcceptOverlay(true);
                placeHideButton(card);
                followBadgeDuringSettle(card);
                if (moved) saveCardLayout();
            }

            @Override
            public void onCardSelectionCleared() {
                setAcceptOverlay(false);
                hideAllHideButtons();
            }
        });

        final float md = getResources().getDisplayMetrics().density;
        for (int i = 0; i < CARD_KEYS.length; i++) {
            final DraggableCardView card = cardForKey(CARD_KEYS[i]);
            // RULES 3: the SU Manager card moves but can never be hidden.
            card.setHideable(!"sumanager".equals(CARD_KEYS[i]));
            android.widget.ImageButton b = new android.widget.ImageButton(this);
            b.setBackgroundResource(R.drawable.bg_card_hide_button);
            b.setImageResource(R.drawable.ic_card_hide);
            b.setImageTintList(ColorStateList.valueOf(0xFF3A3A3C));
            b.setScaleType(android.widget.ImageView.ScaleType.CENTER);
            b.setPadding(0, 0, 0, 0);
            b.setContentDescription("Hide card");
            // Above the lifted card (18dp), below the menu dim layer (30dp).
            b.setElevation(26 * md);
            b.setVisibility(View.GONE);
            b.setOnClickListener(v -> {
                v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                hideCard(card);
            });
            int size = (int) (HIDE_BTN_DP * md);
            android.widget.RelativeLayout.LayoutParams lp =
                    new android.widget.RelativeLayout.LayoutParams(size, size);
            binding.getRoot().addView(b, lp);
            hideButtons[i] = b;
        }

        // Saved order first, then the hidden flags: a hidden card keeps its
        // slot in the stack, so showing it again puts it back where it was.
        List<View> seq = new ArrayList<>();
        for (String key : CardLayoutStore.loadOrder(mDeCtx, CARD_KEYS)) {
            DraggableCardView c = cardForKey(key);
            if (c != null && !seq.contains(c)) seq.add(c);
        }
        stack.applyOrder(seq);
        hiddenCards.addAll(CardLayoutStore.loadHidden(mDeCtx, CARD_KEYS));
        for (String key : hiddenCards) {
            DraggableCardView c = cardForKey(key);
            if (c != null && c.isHideable()) c.setVisibility(View.GONE);
        }
        // Whichever card ends up on top must sit flush, so the 12dp gaps are
        // handed out again now that the hidden ones are out of the way.
        stack.applyOrder(seq);
        // The hidden flags arrive after the log was last composed, and a
        // collapsed advanced-log card takes the log with it (VIS4).
        updateLogVisibility();

        // The accept sheet: full screen, invisible, under the stack (10dp) but
        // above the log scroll and the pills, so a tap anywhere that is not a
        // card accepts the layout (VIS2.2). It has to be a real view: the log
        // scroll and the pills consume their own touches, so a listener on the
        // root layout would never hear the tap.
        android.widget.RelativeLayout.LayoutParams alp =
                new android.widget.RelativeLayout.LayoutParams(
                        android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                        android.view.ViewGroup.LayoutParams.MATCH_PARENT);
        acceptOverlay = new View(this);
        acceptOverlay.setClickable(true);
        acceptOverlay.setElevation(5 * md);
        acceptOverlay.setVisibility(View.GONE);
        acceptOverlay.setOnClickListener(v -> stack.clearSelection());
        binding.getRoot().addView(acceptOverlay, alp);
    }

    /** The accept sheet is up only while a card still carries the outline. */
    private void setAcceptOverlay(boolean on) {
        if (acceptOverlay != null) {
            acceptOverlay.setVisibility(on ? View.VISIBLE : View.GONE);
        }
    }

    /** The badge that belongs to a stack card, or null. */
    private android.widget.ImageButton hideButtonFor(View card) {
        String key = keyForCard(card);
        if (key == null) return null;
        for (int i = 0; i < CARD_KEYS.length; i++) {
            if (CARD_KEYS[i].equals(key)) return hideButtons[i];
        }
        return null;
    }

    /** Show the badge of the lifted card only (VIS1.4). */
    private void showHideButton(View card) {
        hideAllHideButtons();
        android.widget.ImageButton b = hideButtonFor(card);
        if (b == null || !(card instanceof DraggableCardView)
                || !((DraggableCardView) card).isHideable()) {
            return;
        }
        b.setVisibility(View.VISIBLE);
        placeHideButton(card);
    }

    private void hideAllHideButtons() {
        for (android.widget.ImageButton b : hideButtons) {
            if (b != null) b.setVisibility(View.GONE);
        }
        binding.cardStack.clearKeepTouchArea();
    }

    /**
     * Glue the badge to the card's top edge, following it while dragged. Its
     * centre is put on the LEFT edge of the card - the leftmost point of the
     * outlined top edge - so the chip straddles the outline in both directions:
     * half over the card and half over the side margin, half above the card and
     * half below. It is no longer parked a corner radius in from the left, which
     * left it floating over the card instead of on its edge (VIS1.4). The chip is
     * 30dp and the stack is inset 16dp, so the overhang stops 1dp shy of the
     * screen edge and nothing is cut off.
     */
    private void placeHideButton(View card) {
        android.widget.ImageButton b = hideButtonFor(card);
        if (b == null || b.getVisibility() != View.VISIBLE) return;
        float md = getResources().getDisplayMetrics().density;
        int size = b.getWidth() > 0 ? b.getWidth() : Math.round(HIDE_BTN_DP * md);
        int[] at = new int[2];
        int[] root = new int[2];
        card.getLocationInWindow(at);
        binding.getRoot().getLocationInWindow(root);
        float bx = at[0] - root[0] - size / 2f;
        float by = at[1] - root[1] - size / 2f;
        b.setX(bx);
        b.setY(by);
        // ... and tell the stack to let the badge's own taps through.
        CardStackLayout stack = binding.cardStack;
        stack.setKeepTouchArea(bx - stack.getX(), by - stack.getY(),
                bx + size - stack.getX(), by + size - stack.getY());
    }

    /** The badge keeps following the card while it settles into its new slot. */
    private void followBadgeDuringSettle(final View card) {
        binding.cardStack.postDelayed(new Runnable() {
            private int ticks = 16;

            @Override
            public void run() {
                placeHideButton(card);
                if (--ticks > 0) binding.cardStack.postDelayed(this, 16);
            }
        }, 16);
    }

    /** VIS1.4: collapse a card out of the stack for good. The SU Manager card
     *  refuses to be hidden (RULES 3); "Reset UI Layout" brings the rest back. */
    private void hideCard(DraggableCardView card) {
        String key = keyForCard(card);
        if (key == null || !card.isHideable() || hiddenCards.contains(key)) return;
        hiddenCards.add(key);
        // VIS4: collapsing the advanced-log card takes the log with it.
        updateLogVisibility();
        binding.cardStack.clearSelection();
        hideAllHideButtons();
        binding.cardStack.hideCard(card);
        // VIS4: the log follows the advanced-log card, so a collapse anywhere in
        // the stack moves it - but the stack re-reads the window before every
        // frame, so there is nothing left to re-glue here.
        saveCardLayout();
    }

    /** VIS5: back to the shipped order with every card showing again. */
    private void resetCardLayout() {
        CardStackLayout stack = binding.cardStack;
        stack.clearSelection();
        hideAllHideButtons();
        hiddenCards.clear();
        List<View> seq = new ArrayList<>();
        for (String key : CARD_KEYS) {
            DraggableCardView card = cardForKey(key);
            seq.add(card);
            stack.showCard(card);
        }
        stack.applyOrder(seq);
        // VIS4: everything is back where it started, including the log - the
        // stack puts it there on the next frame.
        updateLogVisibility();
        saveCardLayout();
    }

    /** Write the stack order and the hidden flags to dfroot_ui. */
    private void saveCardLayout() {
        List<String> keys = new ArrayList<>();
        for (View v : binding.cardStack.cardOrder()) {
            String key = keyForCard(v);
            if (key != null && !keys.contains(key)) keys.add(key);
        }
        CardLayoutStore.saveOrder(mDeCtx, keys);
        CardLayoutStore.saveHidden(mDeCtx, hiddenCards);
    }

    /** VIS2.1: the scrollable log blacks out while a card is in flight and
     *  shows again once the card has found its spot. */
    private void setLogHiddenForDrag(boolean hidden) {
        if (logHiddenForDrag == hidden) return;
        logHiddenForDrag = hidden;
        // One fade for every reason the log has to come and go (VIS2.1): sliding
        // it away while a card is in the air is the same motion as showing it at
        // all, so it goes through the same place instead of fighting it for the
        // alpha.
        if (hidden) fadeLog(false);
        else updateLogVisibility();
    }

    /** Re-read the SU manager selection when returning to the app: the user may
     *  have installed or uninstalled a manager while we were in the background,
     *  and the Run button has to reflect that immediately. */
    @Override
    protected void onResume() {
        super.onResume();
        loadSuManagerPref();
        updateRunButton();
        startRootWatch();
    }

    @Override
    protected void onPause() {
        stopRootWatch();
        super.onPause();
    }

    /**
     * Watch for root arriving while the app is open, and refresh the recovery reading when it
     * does.
     *
     * <p>The reason this exists is a reboot. It takes both halves of the download-mode answer with
     * it - the vendor clears byte 2, and DirtyFrag's root is a page-cache patch - so on a phone
     * that has just come back the app starts with no su to ask, paints grey with "byte 2 not read
     * here, needs root", and then the owner reroots from this very screen. Nothing used to read the
     * vault again after that: the pill stayed grey, then went red only once the app was killed and
     * reopened, which is a fact nobody should have to know in order to find out that the byte needs
     * writing before they try to flash. Measured on the S25 that developed this feature: exploit
     * back up at 22:52:20, vault finally answering "not-authorized" at 22:52:28 - eight seconds of
     * that gap is the process being killed, not the phone thinking about it.
     *
     * <p>Edge-triggered on purpose. The look itself is three file stats, but what a change
     * triggers is a vault read through su, which a root manager may answer with a prompt. Polling
     * that would be nagging the owner; reacting to su appearing or vanishing is one call per
     * transition. It runs while the activity is in the foreground for the same reason - a watch in
     * the background spends grants nobody is there to answer, and the boot path already covers a
     * device nobody is looking at.
     */
    private void startRootWatch() {
        stopRootWatch();
        // Seeded with the state at resume, so returning to an app that was already rooted does not
        // spend a second reading on top of the one the activity already took.
        mSuWasPresent = D2Writer.suPresent();
        mRootWatch = new Runnable() {
            @Override
            public void run() {
                boolean up = D2Writer.suPresent();
                if (up != mSuWasPresent) {
                    mSuWasPresent = up;
                    // A root that went away is a root that has not been promised anything yet.
                    if (!up) mAutorunTried = false;
                    mExec.execute(MainActivity.this::refreshRecovery);
                }
                mMain.postDelayed(this, ROOT_WATCH_MS);
            }
        };
        mMain.postDelayed(mRootWatch, ROOT_WATCH_MS);
    }

    private void stopRootWatch() {
        if (mRootWatch != null) {
            mMain.removeCallbacks(mRootWatch);
            mRootWatch = null;
        }
    }

    private void setRootedState() {
        setRootedState(true);
    }

    /** Applies the Modules card. Since 3.2 this is a preference write, not a
     *  root operation: bootstrap.c reads disable_modules and touches a
     *  `disable` flag file in every installed module before it starts ksud
     *  (a broken module otherwise bootloops the device). OFF = modules stay
     *  disabled on the next root, ON = modules load. No su required. */
    private void applyModuleState(boolean on) {
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        SharedPreferences.Editor ed = sp.edit();
        if (on) ed.remove("disable_modules");
        else ed.putBoolean("disable_modules", true);
        ed.apply();
        // The subtitle is the whole message. Nothing is announced over the bottom
        // of the screen for a switch the user can already see move.
        binding.modulesSubtitle.setText(on
                ? "Enabled - Active at next reroot"
                : "Disabled - No Modules on reroot");
    }

    // ---- SU manager picker --------------------------------------------------

    /** One candidate: an app that actually ships libksud.so. */
    private static final class SuManagerEntry {
        final String packageName;
        final CharSequence label;

        SuManagerEntry(String pkg, CharSequence label) {
            this.packageName = pkg;
            this.label = label;
        }
    }

    /** Every installed app carrying libksud.so in its native lib dir - exactly
     *  the set ExploitRunner.stageAssets() can use, so anything listed here is
     *  guaranteed to pass the runtime check too. */
    private List<SuManagerEntry> scanSuManagers() {
        List<SuManagerEntry> out = new ArrayList<>();
        PackageManager pm = getPackageManager();
        for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
            if (ai.packageName.equals(getPackageName())) continue;
            if (ai.nativeLibraryDir == null) continue;
            if (!new File(ai.nativeLibraryDir, "libksud.so").exists()) continue;
            out.add(new SuManagerEntry(ai.packageName, pm.getApplicationLabel(ai)));
        }
        out.sort((a, b) -> a.label.toString().compareToIgnoreCase(b.label.toString()));
        return out;
    }

    /** Restores the saved selection, dropping it if that app is gone or no
     *  longer ships libksud.so. */
    private void loadSuManagerPref() {
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        String saved = sp.getString("su_manager", null);
        suManagerPkg = null;
        suManagerLabel = null;
        if (saved != null) {
            for (SuManagerEntry e : scanSuManagers()) {
                if (e.packageName.equals(saved)) {
                    suManagerPkg = e.packageName;
                    suManagerLabel = e.label;
                    break;
                }
            }
            if (suManagerPkg == null) sp.edit().remove("su_manager").apply();
        }
        binding.suManagerSubtitle.setText(suManagerPkg == null
                ? "Not selected - required"
                : suManagerLabel + "  (" + suManagerPkg + ")");
        binding.suManagerSubtitle.setTextColor(suManagerPkg == null
                ? 0xFFE57373 : 0xFF9E9E9E);
    }

    /** OneUI-style rounded popup list over the dim overlay - same look and feel
     *  as the overflow menu, so the picker does not look like a stock spinner. */
    private void showSuManagerPopup() {
        float md = getResources().getDisplayMetrics().density;
        List<SuManagerEntry> apps = scanSuManagers();
        final android.widget.PopupWindow[] pwRef = {null};

        android.widget.LinearLayout box = new android.widget.LinearLayout(this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        box.setBackgroundResource(R.drawable.popup_bg);
        box.setPadding(0, (int) (6 * md), 0, (int) (6 * md));

        if (apps.isEmpty()) {
            TextView none = new TextView(this);
            none.setText("No app with libksud.so found");
            none.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            none.setPadding((int) (20 * md), (int) (12 * md), (int) (20 * md), (int) (12 * md));
            none.setTextColor(0xFF6E6E6E);
            none.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            box.addView(none);
        }

        for (SuManagerEntry e : apps) {
            android.widget.LinearLayout col = new android.widget.LinearLayout(this);
            col.setOrientation(android.widget.LinearLayout.VERTICAL);
            col.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            col.setBackgroundResource(R.drawable.menu_row_highlight);
            col.setPadding((int) (20 * md), 0, (int) (20 * md), 0);

            android.widget.LinearLayout line = new android.widget.LinearLayout(this);
            line.setOrientation(android.widget.LinearLayout.HORIZONTAL);
            line.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            TextView t = new TextView(this);
            t.setText(e.label);
            t.setTextColor(0xFFE8E8E8);
            t.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            line.addView(t, new android.widget.LinearLayout.LayoutParams(
                    0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            if (e.packageName.equals(suManagerPkg)) {
                android.view.View dot = new android.view.View(this);
                dot.setBackgroundResource(R.drawable.dot_white);
                android.widget.LinearLayout.LayoutParams dotLp =
                        new android.widget.LinearLayout.LayoutParams(
                                (int) (7 * md), (int) (7 * md));
                dotLp.setMargins((int) (7 * md), 0, 0, 0);
                line.addView(dot, dotLp);
            }
            col.addView(line, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (26 * md)));

            TextView sub = new TextView(this);
            sub.setText(e.packageName);
            sub.setTextColor(0xFF8E8E8E);
            sub.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 11);
            col.addView(sub);

            col.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                selectSuManager(e);
                if (pwRef[0] != null) pwRef[0].dismiss();
            });
            box.addView(col, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (56 * md)));
        }

        box.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
        int cardW = binding.cardSuManager.getWidth();
        int pw_w = cardW > 0 ? cardW : Math.max(box.getMeasuredWidth(), (int) (240 * md));

        final android.widget.PopupWindow pw = new android.widget.PopupWindow(box,
                pw_w, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, true);
        pw.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(
                android.graphics.Color.TRANSPARENT));
        pw.setOutsideTouchable(true);
        pwRef[0] = pw;
        pw.setOnDismissListener(() ->
                binding.dimOverlay.animate().alpha(0f).setDuration(150)
                        .withEndAction(() -> binding.dimOverlay
                                .setVisibility(View.GONE)).start());

        box.setOutlineProvider(new android.view.ViewOutlineProvider() {
            @Override
            public void getOutline(View view, android.graphics.Outline outline) {
                outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), 26 * md);
            }
        });
        box.setClipToOutline(true);
        box.setElevation(48 * md);

        int[] loc = new int[2];
        binding.cardSuManager.getLocationOnScreen(loc);
        // Centered, NOT card-anchored: the popup is exactly card-wide and the
        // card sits 16dp from each edge, so half the leftover IS the card's own
        // margin. Anchoring to the card's left + 16dp pushed the popup 16dp
        // right, which read as off-centre and clipped its right edge.
        int x = (getResources().getDisplayMetrics().widthPixels - pw_w) / 2;
        int y = loc[1] + binding.cardSuManager.getHeight() + (int) (4 * md);
        binding.dimOverlay.setVisibility(View.VISIBLE);
        binding.dimOverlay.setAlpha(0f);
        binding.dimOverlay.animate().alpha(0.5f).setDuration(150).start();
        box.setPivotX(0f);
        box.setPivotY(0f);
        box.setScaleX(0.9f);
        box.setScaleY(0.9f);
        box.setAlpha(0f);
        pw.showAtLocation(binding.cardSuManager,
                android.view.Gravity.TOP | android.view.Gravity.START, x, y);
        box.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(150)
                .setInterpolator(new android.view.animation.DecelerateInterpolator())
                .start();
    }

    /** Writes the DE pref that bootstrap.c reads as su_manager, then unlocks Run. */
    private void selectSuManager(SuManagerEntry e) {
        mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putString("su_manager", e.packageName).apply();
        suManagerPkg = e.packageName;
        suManagerLabel = e.label;
        binding.suManagerSubtitle.setText(e.label + "  (" + e.packageName + ")");
        binding.suManagerSubtitle.setTextColor(0xFF9E9E9E);
        updateRunButton();
    }

    /** Run needs a manager selected, no failed-run lock and no existing root. */
    private boolean canRun() {
        return suManagerPkg != null && !failedRun && !new File("/dev/df").exists();
    }

    /** Single place that decides the Run pill's look and enabled state. */
    private void updateRunButton() {
        if (running) return;
        if (new File("/dev/df").exists()) {
            setRootedState(true);
            return;
        }
        if (failedRun) {
            setFailedState();
            return;
        }
        boolean ok = suManagerPkg != null;
        binding.btnRun.setEnabled(ok);
        binding.btnRun.setText("Run exploit");
        binding.btnRun.setTextColor(ok ? 0xFFE0E0E0 : 0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(ok ? 0xFF7A7A7A : 0xFF1F1F1F));
        binding.btnRun.setStrokeColor(
                ColorStateList.valueOf(ok ? 0xFFA6A6A6 : 0xFF1F1F1F));
    }

    /**
     * The headline's update state: a lime capsule exactly as wide as the word
     * "DirtyFrag" and the same 44dp module as the two toolbar controls to its right,
     * which wipes in from the left edge and reads "Update" in the headline's place.
     * The version number used to ride here in a small pill over the digits; the
     * headline is the app's own name, and covering it with the one thing that might
     * be worth acting on is both louder and roomier than 4.5pt of digits was.
     *
     * The pill takes the title's slot rather than being drawn over the title: a
     * toolbar lays its children out in a row, so the only way to sit on top of the
     * title would be to be drawn by it, and a ReplacementSpan's pill cannot be 44dp
     * tall inside a text line box. Hence setTitle("") first - the title view goes
     * empty, stops taking space, and the pill moves into that space without anything
     * else in the header shifting. Width only, left edge pinned, 250ms Decelerate:
     * the same one-axis / one-side feel as the Run pill's shrink and the KSU morph.
     */
    private void showUpdatePill() {
        if (binding.updatePill.getVisibility() == View.VISIBLE) return;
        binding.toolbar.setTitle("");
        int word = headlinePx;
        if (word <= 0) {
            // The font failed to load, so no title paint measured the headline. A
            // pill that just fits its own word is honest; a guessed width is not.
            word = Math.round(binding.updateLabel.getPaint().measureText("Update"));
        }
        // Wider than the word it replaces. The headline's advance is exactly as wide
        // as a word, and a capsule cut to that reads as a badge clipped to its own
        // text; 24dp of lime on each side makes it a control with an edge, in the
        // same 44dp module as the two controls to its right. Measured on a 384dp
        // screen it stops clear of the recovery pill on the toolbar's right edge.
        int w = word + Math.round(48 * getResources().getDisplayMetrics().density);
        // The label is given the pill's final width on the way in and centres itself
        // in that, so the growing pill uncovers the word instead of dragging its
        // centre along with its right edge.
        android.widget.FrameLayout.LayoutParams lp =
                (android.widget.FrameLayout.LayoutParams)
                        binding.updateLabel.getLayoutParams();
        lp.width = w;
        binding.updateLabel.setLayoutParams(lp);

        binding.updatePill.setVisibility(View.VISIBLE);
        if (updateMorph != null && updateMorph.isRunning()) updateMorph.cancel();
        updateMorph = android.animation.ValueAnimator.ofInt(0, w);
        updateMorph.setDuration(250);
        updateMorph.setInterpolator(
                new android.view.animation.DecelerateInterpolator());
        updateMorph.addUpdateListener(anim -> setUpdatePillWidth(
                (int) anim.getAnimatedValue()));
        // As in morphKsuToPill: one last layout after the final width frame, so the
        // label inside settles where the finished pill wants it.
        updateMorph.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(android.animation.Animator animation) {
                binding.updatePill.requestLayout();
            }
        });
        updateMorph.start();
    }

    /** The update pill's animated width. layout_gravity="start" welds its left edge
     *  to the headline's, so only the right edge travels. */
    private void setUpdatePillWidth(int px) {
        android.widget.Toolbar.LayoutParams lp =
                (android.widget.Toolbar.LayoutParams)
                        binding.updatePill.getLayoutParams();
        lp.width = px;
        binding.updatePill.setLayoutParams(lp);
    }

    /** SamSU-style GitHub release check: the pill around the version turns
     *  green when the latest published release tag differs from this build's
     *  versionName. Silent on offline / rate-limit / API hiccups. */
    private void checkForAppUpdate() {
        try {
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                    new java.net.URL("https://api.github.com/repos/mitschud/DirtyFrag/releases/latest")
                            .openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setRequestProperty("User-Agent", "DirtyFrag");
            if (conn.getResponseCode() != 200) return;
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream()));
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) body.append(line);
            reader.close();
            String tag = new org.json.JSONObject(body.toString()).optString("tag_name", "");
            if (tag.isEmpty()) {
                Log.i(TAG, "update check: empty tag_name");
                return;
            }
            String latest = tag.replaceFirst("^[vV]", "").trim();
            String mine;
            try {
                mine = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            } catch (Exception e) {
                return;
            }
            if (latest.equalsIgnoreCase(mine)) return;
            Log.i(TAG, "update check: update available (latest=" + latest + ")");
            mMain.post(this::showUpdatePill);
        } catch (Exception e) {
            Log.i(TAG, "update check failed: " + e);
        }
    }

    /**
     * Paints the toolbar dot from the best answer available. The vault itself wins when a su
     * grant let D2Writer read it: those three bytes are exactly what the bootloader weighs
     * before it starts Odin or prints the D2 error, so the dot stops being an estimate.
     * Otherwise the dot falls back to the rootless reading in D2Status - green when download
     * mode is not gated, red when the firmware will answer with the D2 error, grey when this
     * device does not gate download mode at all, which is also what a non-Samsung device gets,
     * so the control never vanishes on a Galaxy for no visible reason.
     *
     * <p>Runs on the background executor. Probing the Settings provider is a binder round trip
     * per key, and reading the vault is a su call - which a root manager may answer with a
     * prompt - so the vault is only reached here when it has answered before or the owner has
     * switched recovery mode on. Both readings land in logcat under this tag as well as in the
     * submenu, so a dot the owner disagrees with is traceable to the facts that produced it
     * rather than being a mystery, which is how the vault-reading attempt at this feature
     * stayed undiagnosable.
     */
    private void refreshRecovery() {
        D2Status.Result r = D2Status.read(this);
        SharedPreferences sp = d2Prefs();
        dropStaleVault(sp);
        boolean armed = sp.getBoolean(PREF_D2_ARMED, false);
        // Whether the byte survives a reboot is something to measure, not to assume. Measured on
        // this S25 (SM-S931B, patch 2026-10-05): eighteen minutes into the boot that followed a
        // write, the vault still answered at_command=1; in the boot after that it answered 0. So
        // the vendor does clear it, just not on the schedule its own service implies. The vault
        // is the only thing that can know, so if there is a su on the path, ask - whatever the
        // saved want says, and especially after a reboot, which is when the saved want is worth
        // least.
        // A su on the path is only worth spending where there is a vault to ask. The harness talks
        // to Samsung's vaultkeeper service, and on firmware that never gated download mode there is
        // no such service and no record - so asking costs the owner an approval prompt for an answer
        // this reading already knows, which is the same mistake the write path refuses to make.
        boolean canAsk = D2Writer.suPresent() && r.supported;
        D2Writer.Vault vault = canAsk ? D2Writer.status(this) : loadVault(sp);
        // The "Autorun Writer" want, honoured here as well as at boot. BootReceiver is the place
        // the byte matters most - a flash is done in the boot the write happens in - but honouring
        // it there takes three things to line up: the receiver switched on, the exploit succeeding
        // unattended, and the boot broadcast reaching this app at all. The last one is not ours to
        // guarantee. On the S25 that developed this feature the boot never did: the boot log holds
        // no "boot:" line from the receiver and no process start for a broadcast, while One UI's
        // own broadcast allowlist complains in the same minutes. So the same want is honoured again
        // against a root that is already in front of us, which is the half the app does control.
        D2Writer.Vault answered = autorunAtRoot(sp, canAsk, vault);
        if (canAsk) saveVault(sp, vault);
        if (answered != vault) saveVault(sp, answered);
        final D2Writer.Vault v = answered;
        mMain.post(() -> {
            mOdin = r;
            mVault = v;
            Log.i(TAG, "recovery: " + r.detail + (v == null ? "" : " | vault: " + v.state));
            applyRecoveryDot(r, v, armed);
        });
    }

    /**
     * The write the "Autorun Writer" switch asks for, run against a root that is already there.
     *
     * <p>Four things have to be true before a byte is written nobody pressed for: there is a vault
     * to ask (a su on the path and firmware that gates download mode), the owner switched the want
     * on, Expert Mode armed the switch that wrote it, and the byte is not already what it should
     * be. A vault that already answers authorised costs one round trip and no write, which is the
     * common case on a boot where the boot path did its job.
     *
     * <p>One attempt per root, not one per refresh: an su that is refused or left unanswered is a
     * state to report, and re-asking a root manager that has just said no is how an unattended
     * feature becomes a prompt loop. The attempt flag is cleared by startRootWatch when su leaves
     * the path, so the next root - which is what a reboot produces - gets its own attempt.
     */
    private D2Writer.Vault autorunAtRoot(SharedPreferences sp, boolean canAsk, D2Writer.Vault v) {
        if (!canAsk || mAutorunTried) return v;
        // Expert Mode is read from prefs rather than from the expertMode field, which is loaded
        // later in onCreate than the first refresh is queued: a background read that started while
        // the activity was still being built would otherwise see the flag as unset and skip a write
        // the owner did ask for.
        if (!sp.getBoolean("expert_mode", false) || !sp.getBoolean(PREF_D2_AUTO, false)) return v;
        if (v != null && v.ok && v.atCommand == 1) return v;
        mAutorunTried = true;
        // Both sinks, the way a press does it. The run log is the artifact the owner can read back
        // and share; until now this write existed only in logcat, so a byte that appeared without a
        // press left no trace in the one place a person looks. Posted because this runs on the vault
        // executor and appendLog draws into the log view; the attempt goes in before the su leaves,
        // so a hung or refused grant still has a line above its absence.
        mMain.post(() -> appendLog(
                "recovery: autorun writer - this root has no authorisation byte, writing it"));
        D2Writer.Vault written = D2Writer.authorize(this);
        Log.i(TAG, "recovery: autorun writer asked the vault: "
                + (written == null ? "no answer" : written.state));
        // The same verdict wording a press prints, so one phrase means one fact whichever of the
        // two paths produced it. The line above is what says nobody pressed.
        if (written != null) mMain.post(() -> appendLog("recovery: " + verdictLine(true, written)));
        return written != null ? written : v;
    }

    /** Whether the boot path exists: the Autorun card's switch is what enables the receiver. */
    private boolean bootPathEnabled() {
        return getPackageManager().getComponentEnabledSetting(
                new ComponentName(this, BootReceiver.class))
                == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
    }

    /**
     * The dot's colour, from whichever of the two readings is the better one. Kept apart from
     * refreshRecovery so the startup read and a tap paint it exactly the same way.
     */
    private void applyRecoveryDot(D2Status.Result r, D2Writer.Vault v, boolean armed) {
        final int lime = 0xFFAEEA00;    // lime, the update pill's all-clear
        final int red = 0xFFE57373;     // the red the failure bar already uses
        final int grey = 0xFF6E6E6E;    // grey: nothing to indicate here
        final int amber = 0xFFFFB300;   // asked for, not confirmed

        int dot;
        if (v != null && v.ok) {
            // Measured, from the vault's own three bytes: the bootloader refuses Odin on
            // [lock=1, maintenance=0, at_command=0].
            dot = v.gated() ? red : lime;
        } else if (armed) {
            // A write was asked for on this boot and no su has answered it yet.
            dot = amber;
        } else {
            // Not asked, not answered: nothing to indicate. The public-API reading cannot see
            // byte 2 and byte 2 is the thing that decides this, so painting the estimate would
            // be painting a guess - which is what made this dot green on a device whose vault
            // said not-authorized.
            dot = grey;
        }
        binding.odinDot.setBackgroundTintList(ColorStateList.valueOf(dot));
    }

    /**
     * Ask the vault for the byte the button asked for, then say out loud what the vault says
     * afterwards and hand that answer back to whatever the press came from.
     *
     * <p>Byte 2 is Samsung's own service escape hatch - AT+SUDDLMOD / AT+FUS set it, and the
     * vendor clears it again on its own schedule, which is measured to be no later than the boot
     * after the one in which it was set - so "on" is a per-boot thing rather than forever, and
     * the want is kept in prefs only so the submenu can say what it intends while a write is
     * still in flight. Nothing here ever puts a vault back as it was: the one byte is all that
     * changes, and the other 31 bytes always go back exactly as they were read.
     *
     * <p>A root manager that has never been asked answers the first press with its own prompt,
     * so a press is exactly one attempt rather than a retry loop: a refused or unanswered su is
     * reported as the state it is, not retried until somebody presses again.
     */
    private void writeDmcFlag(boolean toOn,
                              java.util.function.Consumer<D2Writer.Vault> onDone) {
        if (mOdin != null && !mOdin.supported) {
            // A device whose firmware never gates download mode has no byte worth writing. The
            // switch that could ask for one is inert there and labelled "(no gate)", so this is the
            // same rule approached from the other side: should a press arrive anyway, it is answered
            // with what the card already says rather than with an su grant spent finding out.
            Log.i(TAG, "recovery: firmware does not gate download mode - no byte to write");
            onDone.accept(mVault);
            return;
        }
        SharedPreferences sp = d2Prefs();
        sp.edit().putBoolean(PREF_D2_ARMED, toOn).apply();
        mExec.execute(() -> {
            D2Writer.Vault v = toOn ? D2Writer.authorize(this) : D2Writer.clear(this);
            saveVault(sp, v);
            mMain.post(() -> {
                mVault = v;
                applyRecoveryDot(mOdin, v, toOn);
                String verdict = verdictLine(toOn, v);
                Log.i(TAG, "recovery: " + verdict + " | " + v.detail);
                appendLog("recovery: " + verdict);
                onDone.accept(v);
            });
        });
    }

    /**
     * The one line a flip answers with, written to the run log and nowhere else: the card the
     * press came from is still open in front of the owner and carries the same facts in the three
     * rows the write can change, so a popup at the bottom of the screen would only repeat them
     * and cover the switch that is about to be pressed again. A state that is not the one asked
     * for is named as itself: the service refused, or the record was not a shape the harness
     * writes.
     */
    private static String verdictLine(boolean armed, D2Writer.Vault v) {
        if (!v.ok) {
            return (armed ? "could not switch on: " : "could not clear: ") + v.state;
        }
        if (armed) {
            return v.atCommand == 1
                    ? "recovery mode on - download mode authorised"
                    : "not authorised (" + v.state + ")";
        }
        return v.atCommand == 0
                ? "recovery mode off - authorisation cleared"
                : "still authorised (" + v.state + ")";
    }

    // ---- what the recovery-mode submenu remembers ---------------------------------
    // Device-protected prefs, the same file bootstrap.c reads out of
    // /data/user_de/0/df.root/.
    //
    // Boot-scoped on purpose, because neither half of this survives a reboot. The byte is
    // cleared at the end of every boot by the vendor's own design, and DirtyFrag's root is a
    // page-cache patch, so after a reboot there is no su at all until the exploit has run again
    // - measured on an S25 four minutes into a fresh boot: "su: inaccessible or not found". An
    // answer saved on an earlier boot is a rumour, not an answer, and the app used to show it as
    // one: the pill sat amber and the row said "On" after a reboot while nothing on the device
    // agreed. d2_vault_mono is elapsedRealtime() at the moment of the answer. That counter
    // restarts at boot and never runs backwards inside one, so an answer stamped at a point the
    // counter has not reached can only belong to a boot that is over. A wall-clock stamp would
    // have been the wrong tool: NTP steps the clock mid-boot, which would have thrown away
    // answers that were honest.

    /** What the owner asked byte 2 to be, valid for this boot only. */
    private static final String PREF_D2_ARMED = "d2_at_command";
    /** The opt-in behind the "Autorun Writer" row: ask for the same write again at boot. Read by
     *  BootReceiver, which is the only thing at boot that can supply the root the write needs.
     *  This one is meant to outlive a reboot - everything else here is not. The key keeps the older
     *  name; the row it comes from was "Re-arm after boot" until the card put the writer first. */
    private static final String PREF_D2_AUTO = "d2_auto";
    private static final String PREF_D2_OK = "d2_vault_ok";
    private static final String PREF_D2_STATE = "d2_vault_state";
    private static final String PREF_D2_AT = "d2_at_command_value";
    private static final String PREF_D2_LOCK = "d2_lock";
    private static final String PREF_D2_MAINT = "d2_maintenance";
    private static final String PREF_D2_DETAIL = "d2_vault_detail";
    private static final String PREF_D2_MONO = "d2_vault_mono";

    private SharedPreferences d2Prefs() {
        return mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
    }

    private void saveVault(SharedPreferences sp, D2Writer.Vault v) {
        sp.edit()
                .putBoolean(PREF_D2_OK, v.ok)
                .putString(PREF_D2_STATE, v.state)
                .putInt(PREF_D2_AT, v.atCommand)
                .putInt(PREF_D2_LOCK, v.lock)
                .putInt(PREF_D2_MAINT, v.maintenance)
                .putString(PREF_D2_DETAIL, v.detail)
                .putLong(PREF_D2_MONO, android.os.SystemClock.elapsedRealtime())
                .apply();
    }

    /** The answer kept from the last attempt, or null when the vault was never read on a boot
     *  that is still happening. */
    private static D2Writer.Vault loadVault(SharedPreferences sp) {
        if (!vaultIsFresh(sp)) return null;
        return new D2Writer.Vault(sp.getBoolean(PREF_D2_OK, false),
                sp.getString(PREF_D2_STATE, ""),
                sp.getInt(PREF_D2_AT, -1),
                sp.getInt(PREF_D2_LOCK, -1),
                sp.getInt(PREF_D2_MAINT, -1),
                sp.getString(PREF_D2_DETAIL, ""));
    }

    /** True when an answer is on file and belongs to the boot this process is in. */
    private static boolean vaultIsFresh(SharedPreferences sp) {
        long stamp = sp.getLong(PREF_D2_MONO, -1L);
        return stamp >= 0 && stamp <= android.os.SystemClock.elapsedRealtime();
    }

    /**
     * Forgets the want and the answer when they came from a boot that is over, and logs it once.
     * Left alone they read as the current state: the want survives a reboot, the byte and the
     * root that wrote it do not. The automation opt-in is not dropped - it is the only thing in
     * this block meant to outlive one.
     */
    private void dropStaleVault(SharedPreferences sp) {
        if (vaultIsFresh(sp)) return;
        if (!sp.getBoolean(PREF_D2_ARMED, false) && !sp.contains(PREF_D2_STATE)) return;
        sp.edit().remove(PREF_D2_ARMED)
                .remove(PREF_D2_STATE).remove(PREF_D2_OK).remove(PREF_D2_AT)
                .remove(PREF_D2_LOCK).remove(PREF_D2_MAINT).remove(PREF_D2_DETAIL)
                .remove(PREF_D2_MONO).apply();
        Log.i(TAG, "recovery: want and vault answer from an earlier boot dropped - neither the "
                + "byte nor the root that wrote it survives reboot");
    }
    /**
     * The submenu that hangs off the recovery pill: the verdict the bootloader will reach for a
     * download-mode request, the public inputs that verdict is built from, the device reading that
     * says whether any of this applies here, and the two settings that can be moved from the card.
     * Same rounded card at one fixed width, 46dp rows, hairline separators, scale-in and dimmed
     * backdrop as the overflow menu, because two popups that do different jobs should look like the
     * same control - and because a card that resizes itself between opens moves the switch a finger
     * is already reaching for.
     *
     * <p>Below the rows sit the two things that can be set from here: the write itself, and the
     * automation that asks for it again on the next boot ("Autorun Writer"). Both are OneUI
     * switches, on the card whether or not Expert Mode is on, inert and labelled "(Expert)" until
     * it is, and inert and labelled "(no gate)" on firmware that never gated download mode - so a
     * control is visible before it is armed and says which kind of not-live it is. The writer's
     * thumb is the measured state of the byte, and it is the vault's answer rather than the request
     * that leaves it where it ends up. That is also why the pill opens this submenu instead of
     * acting: nothing here changes Samsung's vault unless the owner has Expert Mode on, the
     * firmware has a gate to write behind, and a switch that says what it will do has been moved.
     *
     * <p>Nothing here answers with a toast. The three rows a write can change are on the card, so
     * a popup at the bottom of the screen would only repeat what the card already says and cover
     * the switch that is about to be pressed again.
     *
     * <p>Everything above them describes this boot and nothing else. The byte is cleared at the
     * end of every boot, and the root that writes it is a page-cache patch a reboot erases, so an
     * answer from a finished boot is dropped rather than displayed - the alternative is a menu
     * that says "Yes" about a device that has already forgotten it.
     */
    private void showRecoveryPopup() {
        D2Status.Result r = mOdin;
        if (r == null) {
            // The first press beat the background read. Reading here costs three
            // binder round trips on a press, which is the one moment that is free.
            r = D2Status.read(this);
            mOdin = r;
        }
        float md = getResources().getDisplayMetrics().density;
        final D2Status.Result shown = r;
        final SharedPreferences sp = d2Prefs();
        dropStaleVault(sp);
        final D2Writer.Vault vault = mVault;

        // One row for what the bootloader will answer a download-mode request with, instead of one
        // row per byte behind that answer. The bootloader weighs the whole record and the write
        // moves the authorisation byte inside it, so the verdict is the thing that can be acted on;
        // the byte the switch controls is already on the card as the thumb's position. Its value
        // cell is kept because a write has to repaint the menu it was asked from rather than leave
        // it describing the vault as it was before the press.
        final android.widget.TextView[] verdictValue = new android.widget.TextView[1];

        android.widget.LinearLayout box = new android.widget.LinearLayout(this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        box.setBackgroundResource(R.drawable.popup_bg);
        box.setPadding(0, (int) (6 * md), 0, (int) (6 * md));

        box.addView(odinRow("DL/Recovery", dlRecoveryLabel(shown, vault), verdictValue), odinRowLp(md));
        box.addView(odinSep(md), odinSepLp(md));
        box.addView(odinRow("Lockscreen", shown.lockscreenLabel()), odinRowLp(md));
        box.addView(odinSep(md), odinSepLp(md));
        box.addView(odinRow("Maintenance Mode", shown.maintenanceLabel()), odinRowLp(md));
        box.addView(odinSep(md), odinSepLp(md));
        box.addView(odinRow("Device", shown.deviceLabel()), odinRowLp(md));

        // Whether either switch below can be moved at all. Expert Mode arms them; the firmware has
        // to have something for them to do. A device whose firmware never gates download mode has
        // no byte to write and no boot to re-arm it for, so both are inert there - and the reason
        // they are inert is said on the row rather than left to a dimmer colour.
        final boolean writerLive = expertMode && shown.supported;

        // The write is a switch, which makes the thumb's position the state of the byte: right
        // means the vault answered at_command=1, measured on this boot. That is also why the answer
        // and not the request is what the switch is left showing - if the service refused, the thumb
        // slides back on its own and the verdict row above changes with it. Inert and labelled
        // "(Expert)" until Expert Mode is armed, inert and labelled "(no gate)" on firmware that
        // never gates download mode, never hidden: a control that only appears once the dangerous
        // setting is armed has to be hunted for again later.
        box.addView(odinSep(md), odinSepLp(md));
        final OneUiSwitch[] writeSw = new OneUiSwitch[1];
        final TextView[] writeName = new TextView[1];
        box.addView(odinToggleRow(switchName("Recovery Writer", writerLive, shown.supported),
                vault != null && vault.ok && vault.atCommand == 1, writerLive,
                writeSw, writeName), odinRowLp(md));
        if (writerLive) {
            writeSw[0].setOnCheckedChangeListener((view, want) -> {
                // One attempt per flip, and the switch is inert while that attempt is in flight:
                // a root manager that is not answering must not be flippable into a loop of su
                // calls. Its answer is the only thing allowed to move the thumb again.
                writeSw[0].setEnabled(false);
                writeName[0].setText(want ? "Writing flag ..." : "Clearing flag ...");
                writeDmcFlag(want, answered -> {
                    verdictValue[0].setText(dlRecoveryLabel(shown, answered));
                    writeName[0].setText(switchName("Recovery Writer", writerLive, shown.supported));
                    // What the vault answered, not what was asked for. The firmware-that-does-not
                    // -gate path hands back the vault as it was, which before a read is no vault
                    // at all - in which case the honest position is off.
                    writeSw[0].setChecked(answered != null && answered.ok
                            && answered.atCommand == 1);
                    writeSw[0].setEnabled(writerLive);
                });
            });
        }

        // Under the write sits the one setting here meant to outlive a reboot: it asks for the same
        // write again on the next boot, which is the only boot where the byte can matter. Both
        // halves of this are per boot - the vendor clears the byte, the reboot erases the root - so
        // wanting it on has to be a step that runs after the exploit does. BootReceiver.armD2Vault
        // performs it; this row only sets the flag in the same device-protected prefs file, and the
        // switch that arms that run is the one that arms the autorun it depends on.
        //
        // A want the boot path would refuse is worse than a want never set, so this switch is inert
        // on firmware that never gates download mode as well as without Expert Mode: what it would
        // ask for is a write nothing on that device can perform. A want stored earlier is left in
        // prefs rather than quietly dropped - the security patch that decides this is only a proxy
        // for the firmware generation, and a proxy that turns out wrong should not have cost the
        // owner a setting they had to opt into in the first place.
        //
        // A switch and not a word to tap: OneUI draws a switch where a setting outlives the screen
        // that sets it, and this is the only flag on the card that does.
        box.addView(odinSep(md), odinSepLp(md));
        final OneUiSwitch[] autoSw = new OneUiSwitch[1];
        // Where the re-arm will actually come from. The boot path is the Autorun card's switch, and
        // One UI withholds the boot broadcast from background apps whatever that switch says - on
        // the S25 that developed this feature it never arrived at all. Saying which of the two the
        // owner has costs one suffix on a row they are already reading, and saves them finding out
        // by rebooting.
        final boolean wantAuto = sp.getBoolean(PREF_D2_AUTO, false);
        String autoName = switchName("Autorun Writer", writerLive, shown.supported);
        if (wantAuto && writerLive && !bootPathEnabled()) autoName += " (at reroot)";
        box.addView(odinToggleRow(autoName,
                wantAuto, writerLive, autoSw, null), odinRowLp(md));
        autoSw[0].setOnCheckedChangeListener((view, checked) ->
                sp.edit().putBoolean(PREF_D2_AUTO, checked).apply());

        // One fixed card, not a card cut to its contents. What is on it is fixed - four rows of
        // label/value and two switches, with labels of similar length - so a measured width only
        // ever moved between opens: the card grew or shrank by a few dp and shifted the switch a
        // finger was already reaching for. 300dp is what the longest label here needs; the clamp
        // keeps it inside a narrow screen.
        int pw_w = Math.min((int) (300 * md),
                getResources().getDisplayMetrics().widthPixels - (int) (16 * md));

        // Everything the two toolbar popups share - the corner under the toolbar they both hang
        // from, the screen darkened behind them, the frame that gives a raised card room to cast a
        // shadow, the scale-in out of that corner - lives in showToolbarCard. Two call sites means
        // two chances for the menu and this card to look like different kinds of control, which is
        // exactly what they no longer are.
        showToolbarCard(box, pw_w, md);
    }

    /**
     * Hang a finished card under the toolbar: right edge dead on {@code menuAnchor}'s, top just
     * below it. Both toolbar popups - the overflow menu and the recovery card - come through here,
     * because everything left in this method belongs to both of them: the corner, the darkened
     * screen behind, the frame a raised card needs to cast a shadow in, and the scale-in that
     * grows out of the corner instead of out of the middle. The overflow menu keeps the returned
     * popup for one reason only: a row inside it closes the menu.
     *
     * <p>The card is not the window's content view - a transparent frame with room around it is.
     * A raised view's shadow is painted by its parent, and a window cut exactly to the card cuts
     * that shadow at the window's own edge, which is what made 48dp of elevation read as a
     * hairline of a line here. The frame gives the shadow somewhere to fall, and the window is the
     * frame's size rather than the card's. Room only counts where the screen has room, so each
     * side is capped by what is actually left of it - the card's right edge sits 8dp from the
     * screen edge, and no frame can conjure shadow out of that.
     *
     * <p>That room now belongs to the window, so a tap in it would otherwise be swallowed. The
     * frame forwards any tap that is not on the card as a dismiss, which is what tapping beside a
     * popup has always meant.
     *
     * @param pw_w the card's width, already settled by the caller; the frame's room is added on
     *             top of it here and subtracted again below, so the card still lands where the
     *             caller put it.
     */
    private android.widget.PopupWindow showToolbarCard(View box, int pw_w, float md) {
        box.setOutlineProvider(new android.view.ViewOutlineProvider() {
            @Override
            public void getOutline(View view, android.graphics.Outline outline) {
                outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), 26 * md);
            }
        });
        box.setClipToOutline(true);
        box.setElevation(72 * md);

        int[] loc = new int[2];
        binding.menuAnchor.getLocationOnScreen(loc);
        int cardRight = loc[0] + binding.menuAnchor.getWidth();
        int screenW = getResources().getDisplayMetrics().widthPixels;
        int room = (int) (40 * md);
        int roomLeft = Math.max(0, cardRight - pw_w);
        int roomRight = Math.max(0, screenW - cardRight);
        int padL = Math.min(room, roomLeft);
        int padR = Math.min(room, roomRight);
        int padT = Math.min(room, Math.max(0, loc[1] + (int) (2 * md)));

        android.widget.FrameLayout frame = new android.widget.FrameLayout(this);
        frame.setPadding(padL, padT, padR, room);
        frame.addView(box, new android.widget.FrameLayout.LayoutParams(
                pw_w, android.view.ViewGroup.LayoutParams.WRAP_CONTENT));

        final android.widget.PopupWindow pw = new android.widget.PopupWindow(frame,
                pw_w + padL + padR, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, true);
        pw.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(
                android.graphics.Color.TRANSPARENT));
        pw.setOutsideTouchable(true);
        frame.setOnTouchListener((view, ev) -> {
            if (ev.getAction() != android.view.MotionEvent.ACTION_DOWN) return false;
            int[] at = new int[2];
            box.getLocationOnScreen(at);
            boolean onCard = ev.getRawX() >= at[0] && ev.getRawX() < at[0] + box.getWidth()
                    && ev.getRawY() >= at[1] && ev.getRawY() < at[1] + box.getHeight();
            if (!onCard) pw.dismiss();
            return !onCard;
        });
        pw.setOnDismissListener(() ->
                binding.dimOverlay.animate().alpha(0f).setDuration(150)
                        .withEndAction(() -> binding.dimOverlay
                                .setVisibility(View.GONE)).start());

        // Darker than the 50% these two popups used to lay over the app. Both cards are #1C1C1C
        // sitting on a dark screen, so the only thing between card and app was the shadow - and a
        // card whose edge cannot be told from the screen behind it reads as part of the screen.
        // Deepening the dim is the half of that separation the shadow cannot supply on its own.
        binding.dimOverlay.setVisibility(View.VISIBLE);
        binding.dimOverlay.setAlpha(0f);
        binding.dimOverlay.animate().alpha(0.75f).setDuration(150).start();
        box.setPivotX(pw_w);
        box.setPivotY(0f);
        box.setScaleX(0.85f);
        box.setScaleY(0.9f);
        box.setAlpha(0f);
        pw.showAtLocation(binding.menuAnchor,
                android.view.Gravity.TOP | android.view.Gravity.START,
                cardRight - pw_w - padL, loc[1] + (int) (2 * md) - padT);
        box.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(150)
                .setInterpolator(new android.view.animation.DecelerateInterpolator())
                .start();
        return pw;
    }

    /**
     * One row of the Odin submenu: label left, value right, on the overflow menu's
     * 46dp row and in its 15sp type. The label takes the menu's grey and the value
     * its near-white, so the half of the pair that can only be read is the dimmer
     * one and the answer is what the eye lands on.
     */
    private android.widget.LinearLayout odinRow(String label, String value) {
        return odinRow(label, value, null);
    }

    /**
     * odinRow again, with the value cell handed back through slot[0]. The three rows a write
     * can change need that: the answer has to be painted into the menu that is already open,
     * not left describing the vault as it was before the press.
     */
    private android.widget.LinearLayout odinRow(String label, String value,
                                                android.widget.TextView[] slot) {
        float md = getResources().getDisplayMetrics().density;
        android.widget.LinearLayout row = new android.widget.LinearLayout(this);
        row.setOrientation(android.widget.LinearLayout.HORIZONTAL);
        row.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
        row.setPadding((int) (20 * md), 0, (int) (20 * md), 0);

        TextView name = new TextView(this);
        name.setText(label);
        name.setTextColor(0xFF9E9E9E);
        name.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
        row.addView(name, new android.widget.LinearLayout.LayoutParams(
                0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView state = new TextView(this);
        state.setText(value);
        state.setTextColor(0xFFE8E8E8);
        state.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
        row.addView(state, new android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT));
        if (slot != null) slot[0] = state;
        return row;
    }

    /**
     * A submenu row whose right-hand half is a OneUI switch instead of a word: the label asks
     * the question, the thumb answers it. The whole row is the touch target - the switch itself
     * is 46x28dp, which is small next to a 46dp row, and OneUI rows have always taken a tap
     * anywhere along them and flipped the switch at their end.
     *
     * <p>{@code enabled} is Expert Mode. An inert switch is drawn dimmed with "(Expert)" on its
     * label instead of being left off the card, so the control is visible before it is armed.
     * The switch handles its own click, so the row has to route the tap to it; when the switch
     * is disabled that route ends at a performClick that refuses, which is the whole of the
     * gating - there is no second copy of the Expert Mode check to fall out of step.
     */
    private android.widget.LinearLayout odinToggleRow(String label, boolean checked,
                                                      boolean enabled,
                                                      OneUiSwitch[] switchSlot,
                                                      android.widget.TextView[] labelSlot) {
        float md = getResources().getDisplayMetrics().density;
        android.widget.LinearLayout row = new android.widget.LinearLayout(this);
        row.setOrientation(android.widget.LinearLayout.HORIZONTAL);
        row.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
        row.setPadding((int) (20 * md), 0, (int) (20 * md), 0);

        TextView name = new TextView(this);
        name.setText(label);
        // The same grey the label half of a value row is drawn in, dimmed further when the
        // switch cannot be moved: the row is still readable, it is just not live.
        name.setTextColor(enabled ? 0xFF9E9E9E : 0xFF6F6F6F);
        name.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
        row.addView(name, new android.widget.LinearLayout.LayoutParams(
                0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        OneUiSwitch sw = new OneUiSwitch(this);
        sw.setCheckedQuiet(checked);
        sw.setEnabled(enabled);
        if (!enabled) sw.setAlpha(0.4f);
        row.addView(sw, new android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT));

        row.setOnClickListener(v -> sw.performClick());
        if (switchSlot != null) switchSlot[0] = sw;
        if (labelSlot != null) labelSlot[0] = name;
        return row;
    }

    /** The overflow menu's row height, so the two popups are cut from one cloth. */
    private static android.widget.LinearLayout.LayoutParams odinRowLp(float md) {
        return new android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md));
    }

    /** The hairline between two rows of the Odin submenu. */
    private android.view.View odinSep(float md) {
        android.view.View sep = new android.view.View(this);
        sep.setBackgroundColor(0xFF3F3F3F);
        return sep;
    }

    /** That hairline, inset 20dp from the card's edges exactly like the menu's. */
    private static android.widget.LinearLayout.LayoutParams odinSepLp(float md) {
        android.widget.LinearLayout.LayoutParams lp =
                new android.widget.LinearLayout.LayoutParams(
                        android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                        Math.max(1, (int) md));
        lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
        return lp;
    }

    /**
     * The card's one verdict row: what the bootloader will answer a download-mode request with,
     * which is also what having recovery mode on or off amounts to for this firmware. Only the
     * vault's own three bytes can answer it - the bootloader weighs [lock, maintenance, at_command]
     * and refuses Odin on [1, 0, 0] - so the row says "Unknown" whenever they have not been read,
     * and the public-API reading has no part in the wording: it is missing the one byte that
     * decides the answer in both directions. A device whose firmware never gated download mode at
     * all gets that said out loud, because "Unknown" there would promise a reading that can never
     * arrive - and that is said ahead of any answer cached from earlier in the boot, so the card
     * cannot show a verdict for a firmware that has no gate able to produce one. The byte the
     * writer switch controls is not given a row of its own any more; its thumb is that byte, on the
     * same card.
     */
    private static String dlRecoveryLabel(D2Status.Result est, D2Writer.Vault v) {
        if (!est.supported) return "Not gated here";
        if (v != null && v.ok) return v.gated() ? "D2 Blocked" : "Allowed";
        return "Unknown";
    }

    /**
     * What a toggle row is called: bare when the switch can be moved, "(Expert)" when the arming
     * switch is off, "(no gate)" when this firmware has nothing for the switch to do. Two different
     * reasons for being inert should not offer the same excuse, and the difference between "not
     * armed yet" and "will never be live here" is the difference between coming back later and
     * coming back never.
     */
    private static String switchName(String base, boolean live, boolean supported) {
        if (!supported) return base + " (no gate)";
        return live ? base : base + " (Expert)";
    }


    /** Failure presentation: left bar label "Failure", right label "Reboot",
     *  bars + labels red, run pill greyed out like the Running/Rooted state.
     *  The pill stays disabled because the vendor patch is page-cache only:
     *  retrying without rebooting would fail the same way. */
    private void setFailedState() {
        failedRun = true;
        binding.twoStep.setFailed(true);
        binding.twoStep.setSeg1(seg1, "Failure");
        binding.twoStep.setSeg2(1f, "Reboot", 0xFFE57373);
        binding.btnRun.setEnabled(false);
        binding.btnRun.setText("Run exploit");
        binding.btnRun.setTextColor(0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
        binding.btnRun.setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
        setCompactButton(false, false);
    }

    private void setRootedState(boolean rooted) {
        runArmed = false;
        // Not rooted does not mean runnable: the manager still has to be picked
        // and a failed run locks the pill until reboot.
        boolean ok = !rooted && canRun();
        int fg = (rooted || !ok) ? 0xFF6E6E6E : 0xFFE0E0E0;
        int bg = (rooted || !ok) ? 0xFF1F1F1F : 0xFF7A7A7A;
        int stroke = (rooted || !ok) ? 0xFF1F1F1F : 0xFFA6A6A6;
        binding.btnRun.setEnabled(ok);
        binding.btnRun.setText(rooted ? "Rooted" : "Run exploit");
        binding.btnRun.setTextColor(fg);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(bg));
        binding.btnRun.setStrokeColor(ColorStateList.valueOf(stroke));
        // Rooted/running: shrink the pill left and pop the KSU circle next to
        // it (lit when rooted); fresh run state: full-width pill, no circle.
        setCompactButton(rooted, rooted);
    }

    /** Shrinks the main pill to the left and pops the KSU launcher circle
     *  next to it (compact=true, ksuLit=lit after successful root), or
     *  restores the full-width pill. */
    private void setCompactButton(boolean compact, boolean ksuLit) {
        // Fresh pill: 48% wide starting 26% in from the parent's left edge → right
        // edge at 74%. Compact: pill + 12dp gap + 54dp circle must occupy the same
        // 48% total (left edge pinned), so pill = 48% - extras.
        float measured = ((View) binding.btnRun.getParent()).getWidth();
        if (measured <= 0) measured = getResources().getDisplayMetrics().widthPixels;
        final float parentW = measured;
        float density = getResources().getDisplayMetrics().density;
        float target = 0.48f;
        if (compact) {
            float extrasPx = (KSU_GAP_DP + KSU_CIRCLE_DP) * density;
            target = Math.max(0.20f, 0.48f - extrasPx / parentW);
        }
        android.animation.ValueAnimator a =
                android.animation.ValueAnimator.ofFloat(pillPercent, target);
        a.setDuration(250);
        a.addUpdateListener(anim -> {
            pillPercent = (float) anim.getAnimatedValue();
            applyRunPillGeometry(parentW);
        });
        a.start();
        // The launcher pill ends up exactly as wide as the shrunken Run pill
        // (measured off the user's mockups: 331 vs 332 px on the S25), which is
        // what fills the old 100dp right-hand deadzone and mirrors the share
        // circle on the left.
        int ksuPillPx = (int) (target * parentW);
        int ksuCirclePx = (int) (KSU_CIRCLE_DP * density);
        binding.btnKsu.setEnabled(ksuLit);
        boolean wasVisible = binding.btnKsu.getVisibility() == View.VISIBLE
                && binding.btnKsu.getAlpha() > 0.99f;
        binding.btnKsu.setBackgroundTintList(ColorStateList.valueOf(
                ksuLit ? 0xFFB0B0B0 : 0xFF1F1F1F));
        // Dark ink on the lit pill, mid-grey on the unlit one - same grey as
        // the share glyph.
        binding.ksuChevron.setImageTintList(ColorStateList.valueOf(
                ksuLit ? 0xFF1F1F1F : 0xFF6E6E6E));
        if (compact && !wasVisible) {
            // First appearance: pop in as a circle. The morph is chained to the
            // pop-in's end so the Run pill has already finished shrinking - its
            // right edge is the launcher's start anchor, so the launcher's left
            // edge must be stable before we animate the width.
            setKsuWidth(ksuCirclePx);
            binding.ksuLabel.setAlpha(0f);
            binding.btnKsu.setVisibility(View.VISIBLE);
            binding.btnKsu.setAlpha(0f);
            binding.btnKsu.setScaleX(0.6f);
            binding.btnKsu.setScaleY(0.6f);
            binding.btnKsu.postDelayed(() -> binding.btnKsu.animate()
                    .alpha(1f).scaleX(1f).scaleY(1f).setDuration(180)
                    .withEndAction(() -> {
                        settleKsuTint(ksuLit);
                        morphKsuToPill(ksuLit, ksuPillPx, ksuCirclePx);
                    }).start(), 150);
        } else if (compact) {
            // Already visible (state change): stay in place, recolor + grow.
            settleKsuTint(ksuLit);
            morphKsuToPill(ksuLit, ksuPillPx, ksuCirclePx);
        } else {
            binding.ksuLabel.animate().alpha(0f).setDuration(150).start();
            binding.btnKsu.animate().alpha(0f).scaleX(0.6f).scaleY(0.6f)
                    .setDuration(200)
                    .withEndAction(() -> {
                        binding.btnKsu.setVisibility(View.GONE);
                        setKsuWidth(ksuCirclePx);
                    })
                    .start();
        }
    }

    /** After the lit circle settles, ease it slightly towards grey. */
    private void settleKsuTint(boolean ksuLit) {
        if (!ksuLit) return;
        android.animation.ValueAnimator g =
                android.animation.ValueAnimator.ofFloat(0f, 1f);
        g.setStartDelay(250);
        g.setDuration(300);
        g.addUpdateListener(anim -> binding.btnKsu
                .setBackgroundTintList(ColorStateList.valueOf(
                        mixColor(0xFFB0B0B0, 0xFF9A9A9E,
                                (float) anim.getAnimatedValue()))));
        g.start();
    }

    /** Circle -> pill (or back): width only, left edge pinned, 250ms
     *  Decelerate - the same one-axis / one-side feel as the Run pill's
     *  shrink. The label fades in as the pill opens up. */
    private void morphKsuToPill(boolean lit, int pillPx, int circlePx) {
        int from = binding.btnKsu.getWidth();
        int to = lit ? pillPx : circlePx;
        if (from <= 0 || from == to) return;
        if (ksuMorph != null && ksuMorph.isRunning()) ksuMorph.cancel();
        ksuMorph = android.animation.ValueAnimator.ofInt(from, to);
        ksuMorph.setDuration(250);
        ksuMorph.setInterpolator(
                new android.view.animation.DecelerateInterpolator());
        ksuMorph.addUpdateListener(
                anim -> setKsuWidth((int) anim.getAnimatedValue()));
        // One final re-layout after the last width frame: the label and the
        // chevron are positioned by the FrameLayout, and a mid-morph width can
        // leave them stale (seen on device: the label stayed at the circle's
        // left edge instead of moving into the pill). ValueAnimator has no
        // withEndAction - that is ViewPropertyAnimator's API.
        ksuMorph.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(android.animation.Animator animation) {
                binding.btnKsu.requestLayout();
            }
        });
        ksuMorph.start();
        binding.ksuLabel.animate().alpha(lit ? 1f : 0f)
                .setStartDelay(lit ? 120 : 0).setDuration(220).start();
    }

    /**
     * The Run pill's box in pixels: {@code pillPercent} of the parent's width, inset
     * from its left edge by {@code PILL_INSET_FRACTION} of that width. ConstraintLayout
     * used to say this with matchConstraintPercentWidth plus a vertical guideline;
     * RelativeLayout has neither, and a percentage of the parent is not something it
     * can declare at all - so the pill stays wrap_content in the XML and this method
     * does the arithmetic once somebody knows how wide the parent is. setCompactButton
     * drives it frame by frame while the width animates; onCreate drives it once for
     * the first pass, before anything has been measured.
     */
    private void applyRunPillGeometry(float parentW) {
        if (parentW <= 0) parentW = ((View) binding.btnRun.getParent()).getWidth();
        if (parentW <= 0) parentW = getResources().getDisplayMetrics().widthPixels;
        android.widget.RelativeLayout.LayoutParams lp =
                (android.widget.RelativeLayout.LayoutParams)
                        binding.btnRun.getLayoutParams();
        lp.leftMargin = (int) (PILL_INSET_FRACTION * parentW);
        lp.width = (int) (pillPercent * parentW);
        binding.btnRun.setLayoutParams(lp);
        // The share circle mirrors the pill's left edge, so it takes the same
        // arithmetic: its XML pins it to the parent's start and this puts the
        // inset in, exactly like the pill's. It cannot hang off the pill with
        // layout_toStartOf - the anchor is resolved against the pill's rule
        // (parent start), not against the leftMargin set two lines above, and
        // on device that left the circle at x = -186: drawn, clickable, gone.
        android.widget.RelativeLayout.LayoutParams shareLp =
                (android.widget.RelativeLayout.LayoutParams)
                        binding.btnShareLog.getLayoutParams();
        if (shareLp.width > 0) {
            float gap = KSU_GAP_DP * getResources().getDisplayMetrics().density;
            // Math.round, not a truncate: btnKsu's 12dp layout_marginStart rounds
            // to 34 px, and a truncated 33 here left the row visibly lopsided.
            shareLp.leftMargin = Math.max(0,
                    lp.leftMargin - Math.round(gap) - shareLp.width);
            binding.btnShareLog.setLayoutParams(shareLp);
        }
    }

    /** The launcher's animated width. layout_toEndOf="@id/btnRun" welds its left
     *  edge to the Run pill's right edge (plus the 12dp gap) while the right edge
     *  travels - the plain-RelativeLayout reading of the old
     *  layout_constraintHorizontal_bias="0". */
    private void setKsuWidth(int px) {
        android.widget.RelativeLayout.LayoutParams lp =
                (android.widget.RelativeLayout.LayoutParams)
                        binding.btnKsu.getLayoutParams();
        lp.width = px;
        binding.btnKsu.setLayoutParams(lp);
    }

    /** Opens the SU manager that is actually selected - pre-3.2 this walked a
     *  hardcoded package list that no longer matches reality. */
    private void openKsu() {
        if (suManagerPkg == null) {
            // Nothing to say: the launcher circle is only lit once a manager is
            // picked, so getting here is a no-op rather than an error.
            return;
        }
        Intent launch = getPackageManager().getLaunchIntentForPackage(suManagerPkg);
        if (launch == null) {
            Log.i(TAG, "no launch intent for " + suManagerPkg);
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(launch);
    }

    private static int mixColor(int a, int b, float t) {
        int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF;
        int br = (b >> 16) & 0xFF, bg = (b >> 8) & 0xFF, bb = b & 0xFF;
        return 0xFF000000
                | (Math.round(ar + (br - ar) * t) << 16)
                | (Math.round(ag + (bg - ag) * t) << 8)
                | Math.round(ab + (bb - ab) * t);
    }

    /** Saves the current log to Downloads and opens the Downloads screen. */
    private void shareLog() {
        String log = logBuffer.length() > 0 ? logBuffer.toString() : readLastLog();
        if (log.trim().isEmpty()) {
            return;
        }
        try {
            ContentValues values = new ContentValues();
            values.put(MediaStore.Downloads.DISPLAY_NAME, "dirtyfrag_log.txt");
            values.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
            Uri uri = getContentResolver().insert(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (uri != null) {
                try (java.io.OutputStream out = getContentResolver().openOutputStream(uri)) {
                    out.write(log.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "save log failed", e);
        }
        try {
            startActivity(new Intent(android.app.DownloadManager.ACTION_VIEW_DOWNLOADS));
        } catch (Exception e) {
            Log.e(TAG, "open downloads failed", e);
        }
    }

    private void runExploit() {
        // bootstrap.c reads soft_reboot straight out of the DE prefs, so mirror
        // the Autorun card's choice into the key it reads right before launch.
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        boolean autoSoftReboot = sp.getBoolean("auto_soft_reboot", false);
        sp.edit().putBoolean("soft_reboot", autoSoftReboot).apply();
        lastFailReason = null;
        try {
            int rc = ExploitRunner.run(mDeCtx, this);
            if (rc != 0) {
                // 0 ok, 1 ksud/bootstrap error, 2 poll timeout or bad setup,
                // 3 failed to patch files (see exp.c markers[]).
                String why = lastFailReason != null ? lastFailReason
                        : rc == 1 ? "ksud nonzero exit"
                        : rc == 2 ? "check logcat & dmesg"
                        : "failed to patch files";
                report("\n=== exploit failed: " + why + " ===\n");
            }
            mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", rc == 0).apply();
        } catch (Exception e) {
            Log.e(TAG, "exploit exception", e);
            report("\nexception: " + e + "\n");
        } finally {
            mMain.post(() -> {
                running = false;
                boolean rooted = new File("/dev/df").exists();
                if (rooted) {
                    setRootedState(true);
                    binding.twoStep.setSeg2(1f, "Verified", 0xFFFFFFFF);
                } else {
                    setFailedState();
                    setRootedState(false);
                }
                updateLogVisibility();
                // The root this screen just put there is the fastest chance there is to read the
                // vault behind it, and the download-mode verdict is that read. The root watch sees
                // the same transition a beat later; asking now is what keeps the pill from
                // describing a boot that ended minutes ago.
                if (rooted) mExec.execute(MainActivity.this::refreshRecovery);
            });
        }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            Log.i(TAG, "no browser for " + url);
        }
    }

}
