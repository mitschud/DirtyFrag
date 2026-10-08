package df.root;

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
import android.widget.Toast;
import androidx.core.content.res.ResourcesCompat;

import androidx.appcompat.app.AppCompatActivity;

import df.root.databinding.ActivityMainBinding;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity implements IReporter {

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
    private android.animation.ValueAnimator ksuMorph;
    private VersionPillSpan pillSpan;
    private TextView titleView;
    private boolean updateAvailable;
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

    /** Visibility of log / share button / progress bar, composed from the
     *  advanced-log setting and whether any run data exists. The log block
     *  needs the switch; the share circle does not - a finished run can always
     *  be saved. */
    private void updateLogVisibility() {
        boolean hasRun = logBuffer.length() > 0
                || (lastLogFile != null && lastLogFile.exists());
        boolean showLog = advancedLog && hasRun;
        binding.outputScroll.setVisibility(showLog ? View.VISIBLE : View.GONE);
        // Share circle: any FINISHED run, advanced log on or off. Still hidden
        // while a run is in flight (the log is being written) and shown for a
        // saved log from a previous boot, which is finished by definition.
        setShareButtonVisible(hasRun && !running);
        // Progress bar is the simple status: always visible.
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
            StringBuilder sb = new StringBuilder();
            while (m.find()) m.appendReplacement(sb, java.util.regex.Matcher
                    .quoteReplacement(m.group().toLowerCase()));
            m.appendTail(sb);
            return sb.toString();
        } catch (IOException e) {
            return "";
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mDeCtx = createDeviceProtectedStorageContext();
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Version tag flowing right after the header title.
        SpannableString title = new SpannableString("DirtyFrag 1.11");
        pillSpan = new VersionPillSpan(0.45f);
        title.setSpan(pillSpan, 10, title.length(),
                SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE);
        binding.toolbar.setTitle(title);
        // NOTE: no setSupportActionBar() - it makes the ActionBar delegate draw
        // the title and ignore the toolbar's titleTextAppearance (breaks bold).
        // The toolbar renders its own title via app:titleTextAppearance.

        // Update check (SamSU-style): the pill around the version turns green
        // when GitHub has a newer release; tapping the title opens the releases
        // page (only while an update is flagged, so it stays a no-op otherwise).
        mExec.execute(this::checkForAppUpdate);

        // D2 vault status (Samsung VaultKeeper): Odin flashing allowed or
        // locked. Read-only; non-Samsung devices show "not available".

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

        // Force real bold (wght 700) One UI Sans on the toolbar title TextView.
        binding.toolbar.post(() -> {
            Typeface base = ResourcesCompat.getFont(this, R.font.inter_vf);
            if (base == null) return;
            Typeface bold = Typeface.create(base, 700, false);
            for (int i = 0; i < binding.toolbar.getChildCount(); i++) {
                View child = binding.toolbar.getChildAt(i);
                if (child instanceof TextView) {
                    titleView = (TextView) child;
                    titleView.setTypeface(bold);
                    titleView.setOnClickListener(v -> {
                        if (updateAvailable) openUrl(
                                "https://github.com/mitschud/DirtyFrag/releases");
                    });
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
        binding.switchAdvancedLog.setOnCheckedChangeListener((btn, checked) -> {
            advancedLog = checked;
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("advanced_log", checked).apply();
            updateLogVisibility();
        });
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
            ((com.google.android.material.button.MaterialButton) binding.btnRun)
                    .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
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

            // -- Github Page row --
            TextView ghRow = new TextView(this);
            ghRow.setBackgroundResource(R.drawable.menu_row_highlight);
            ghRow.setText("Github Page");
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

            // -- Expert Mode row: white dot appears when enabled --
            android.widget.LinearLayout exRow = new android.widget.LinearLayout(this);
            exRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            exRow.setPadding((int) (20 * md), 0, 0, 0);
            TextView exText = new TextView(this);
            exRow.setBackgroundResource(R.drawable.menu_row_highlight);
            exText.setText("Expert Mode");
            exText.setTextColor(0xFFE8E8E8);
            exText.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            exRow.addView(exText);
            final android.view.View[] dotRef = {null};
            android.view.View dot = new android.view.View(this);
            dot.setBackgroundResource(R.drawable.dot_white);
            android.widget.LinearLayout.LayoutParams dotLp =
                    new android.widget.LinearLayout.LayoutParams(
                            (int) (7 * md), (int) (7 * md));
            dotLp.setMargins((int) (7 * md), 0, 0, 0);
            dot.setVisibility(expertMode ? View.VISIBLE : View.GONE);
            exRow.addView(dot, dotLp);
            dotRef[0] = dot;
            exRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                expertMode = !expertMode;
                createDeviceProtectedStorageContext()
                        .getSharedPreferences("dfroot", MODE_PRIVATE)
                        .edit().putBoolean("expert_mode", expertMode).apply();
                applyExpertMode();
                if (dotRef[0] != null)
                    dotRef[0].setVisibility(expertMode ? View.VISIBLE : View.GONE);
            });
            box.addView(exRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Remove KSU/KSUD row: 3-tap confirm, greyed out until a manager
            //    is picked. Pre-3.2 this hardcoded me.weishu.kernelsu; it now
            //    targets whichever manager is actually selected. --
            final boolean haveManager = suManagerPkg != null;
            android.widget.LinearLayout rmCol = new android.widget.LinearLayout(this);
            rmCol.setOrientation(android.widget.LinearLayout.VERTICAL);
            rmCol.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            rmCol.setPadding((int) (20 * md), 0, (int) (20 * md), 0);
            TextView rmTitle = new TextView(this);
            rmCol.setBackgroundResource(R.drawable.menu_row_highlight);
            rmTitle.setText("Remove KSU/KSUD");
            rmTitle.setGravity(android.view.Gravity.START);
            rmTitle.setTextColor(haveManager ? 0xFFE8E8E8 : 0xFF6E6E6E);
            rmTitle.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            rmCol.addView(rmTitle);
            TextView rmSub = new TextView(this);
            rmSub.setText(haveManager ? "Click 3 times" : "No SU manager selected");
            rmSub.setGravity(android.view.Gravity.START);
            rmSub.setTextColor(haveManager ? 0xFF8E8E8E : 0xFF5A5A5A);
            rmSub.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 11);
            rmCol.addView(rmSub);
            final int[] taps = {0};
            rmCol.setOnClickListener(v2 -> {
                if (!haveManager) return;
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                taps[0]++;
                if (taps[0] == 1) {
                    rmTitle.setText("Are you sure");
                    rmSub.setText("Click 2 times");
                    return;
                }
                if (taps[0] == 2) {
                    rmTitle.setText("One more click");
                    rmSub.setText("Click 1 time");
                    return;
                }
                if (pwRef[0] != null) pwRef[0].dismiss();
                // Deliberately NOT calling `ksud uninstall`: its upstream
                // implementation force-flashes a stored boot image when a backup
                // exists and reboots the device after 5 seconds - surprises we
                // don't want. DirtyFrag's kernel side is a page-cache patch that
                // a plain reboot clears, so removing the manager app is the job.
                try {
                    Intent un = new Intent(Intent.ACTION_DELETE,
                            Uri.fromParts("package", suManagerPkg, null));
                    un.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(un);
                } catch (Exception e) {
                    Toast.makeText(MainActivity.this,
                            "Uninstall prompt unavailable", Toast.LENGTH_SHORT).show();
                }
            });
            box.addView(rmCol, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (58 * md)));

            // Width: content, but at least 210dp so the popup reads properly.
            box.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
            int pw_w = Math.max(box.getMeasuredWidth(), (int) (190 * md));

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

            // Centered separators between the rows.
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

            box.setOutlineProvider(new android.view.ViewOutlineProvider() {
                @Override
                public void getOutline(View view, android.graphics.Outline outline) {
                    outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), 26 * md);
                }
            });
            box.setClipToOutline(true);
            box.setElevation(48 * md);

            int[] loc = new int[2];
            binding.menuAnchor.getLocationOnScreen(loc);
            int x = loc[0] + binding.menuAnchor.getWidth() - pw_w;
            int y = loc[1] + (int) (2 * md);
            binding.dimOverlay.setVisibility(View.VISIBLE);
            binding.dimOverlay.setAlpha(0f);
            binding.dimOverlay.animate().alpha(0.5f).setDuration(150).start();
            box.setPivotX(pw_w);
            box.setPivotY(0f);
            box.setScaleX(0.85f);
            box.setScaleY(0.9f);
            box.setAlpha(0f);
            pw.showAtLocation(binding.menuAnchor,
                    android.view.Gravity.TOP | android.view.Gravity.START, x, y);
            box.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(150)
                    .setInterpolator(new android.view.animation.DecelerateInterpolator())
                    .start();
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

    /** Re-read the SU manager selection when returning to the app: the user may
     *  have installed or uninstalled a manager while we were in the background,
     *  and the Run button has to reflect that immediately. */
    @Override
    protected void onResume() {
        super.onResume();
        loadSuManagerPref();
        updateRunButton();
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
        binding.modulesSubtitle.setText(on
                ? "Enabled - Active at next reroot"
                : "Disabled - No Modules on reroot");
        Toast.makeText(this,
                on ? "KSU modules enabled - applies at next root"
                        : "KSU modules disabled - applies at next root",
                Toast.LENGTH_SHORT).show();
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
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(ok ? 0xFFA6A6A6 : 0xFF1F1F1F));
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
            mMain.post(() -> {
                updateAvailable = true;
                // Grow the pill from its left edge into the lime update state,
                // same 250ms feel as the Run pill's shrink.
                if (titleView != null) {
                    android.animation.ValueAnimator a =
                            android.animation.ValueAnimator.ofFloat(0f, 1f);
                    a.setDuration(250);
                    a.addUpdateListener(anim -> {
                        pillSpan.setProgress((float) anim.getAnimatedValue());
                        titleView.invalidate();
                    });
                    a.start();
                } else {
                    pillSpan.setProgress(1f);
                }
            });
        } catch (Exception e) {
            Log.i(TAG, "update check failed: " + e);
        }
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
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
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
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(stroke));
        // Rooted/running: shrink the pill left and pop the KSU circle next to
        // it (lit when rooted); fresh run state: full-width pill, no circle.
        setCompactButton(rooted, rooted);
    }

    /** Shrinks the main pill to the left and pops the KSU launcher circle
     *  next to it (compact=true, ksuLit=lit after successful root), or
     *  restores the full-width pill. */
    private void setCompactButton(boolean compact, boolean ksuLit) {
        // Fresh pill: 48% wide starting at the 26% guideline → right edge at
        // 74%. Compact: pill + 12dp gap + 54dp circle must occupy the same
        // 48% total (left edge pinned), so pill = 48% - extras.
        float parentW = ((View) binding.btnRun.getParent()).getWidth();
        if (parentW <= 0) parentW = getResources().getDisplayMetrics().widthPixels;
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
            androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                    (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                            binding.btnRun.getLayoutParams();
            lp.matchConstraintPercentWidth = pillPercent;
            binding.btnRun.setLayoutParams(lp);
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

    /** The launcher's animated width. layout_constraintHorizontal_bias="0"
     *  welds its left edge to the Run pill while the right edge travels. */
    private void setKsuWidth(int px) {
        androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                        binding.btnKsu.getLayoutParams();
        lp.width = px;
        binding.btnKsu.setLayoutParams(lp);
    }

    /** Opens the SU manager that is actually selected - pre-3.2 this walked a
     *  hardcoded package list that no longer matches reality. */
    private void openKsu() {
        if (suManagerPkg == null) {
            Toast.makeText(this, "No SU manager selected", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent launch = getPackageManager().getLaunchIntentForPackage(suManagerPkg);
        if (launch == null) {
            Toast.makeText(this, suManagerPkg + " cannot be launched",
                    Toast.LENGTH_SHORT).show();
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
            });
        }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            Toast.makeText(this, "No browser found", Toast.LENGTH_SHORT).show();
        }
    }

}
