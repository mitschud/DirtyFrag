package df.root;

import android.content.Context;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Intent;
import android.content.res.ColorStateList;
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
    private VersionPillSpan pillSpan;
    private TextView titleView;
    private boolean updateAvailable;
    private boolean moduleRefresh;
    private final androidx.activity.result.ActivityResultLauncher<String> ksudPicker =
        registerForActivityResult(
                new androidx.activity.result.contract.ActivityResultContracts.GetContent(),
                uri -> {
                    if (uri != null) copyKsud(uri);
                });
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
                // Drop internal patch/hook details and result headers.
                if (t.contains("hook=") || t.matches("\\*+SUCCESS\\*+")
                        || t.contains("exploit success")) {
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

    /** Translates raw native log lines into two-step progress-bar states. */
    private void driveProgress(String t) {
        if (t.isEmpty()) return;
        switch (t) {
            case "=== setup ===":
                exploitPhase = "setup";
                setSeg1(0.05f);
                break;
            case "=== exploit ===":
                exploitPhase = "exploit";
                setSeg1(0.15f);
                break;
            case "=== cleanup ===":
                exploitPhase = "cleanup";
                cleanupSteps = 0;
                setSeg1(1f);
                setSeg2(0.05f, getString(R.string.verification), 0xFFFFFFFF);
                break;
            default:
                break;
        }
        if (exploitPhase.equals("setup") && t.startsWith("ksud staged")) {
            setSeg1(0.10f);
        }
        if (exploitPhase.equals("exploit") && t.startsWith("patched")) {
            if (t.contains("crash_dump64")) {
                setSeg1(0.30f);
            } else if (t.contains("libbinderdebug")) {
                setSeg1(0.55f);
            } else if (t.contains("libc++.so")) {
                setSeg1(Math.min(0.80f, seg1 + 0.05f));
            }
        }
        if (t.startsWith("* triggering")) {
            setSeg1(0.85f);
        }
        if (t.startsWith("libc++: mutex acquired")) {
            setSeg1(0.95f);
        }
        if (exploitPhase.equals("cleanup")
                && (t.startsWith("* restore") || t.startsWith("* cache dropped"))) {
            cleanupSteps++;
            setSeg2(Math.min(1f, cleanupSteps / 3f), getString(R.string.verification), 0xFFFFFFFF);
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
     *  advanced-log setting and whether any run data exists. */
    private void updateLogVisibility() {
        boolean hasRun = logBuffer.length() > 0
                || (lastLogFile != null && lastLogFile.exists());
        boolean showLog = advancedLog && hasRun;
        binding.outputScroll.setVisibility(showLog ? View.VISIBLE : View.GONE);
        binding.btnShareLog.setVisibility(showLog ? View.VISIBLE : View.GONE);
        // Progress bar is the simple status: always visible.
    }

    /** "=== setup ===" -> "SETUP"; "=== exploit failed: x ===" -> "EXPLOIT FAILED: X". */
    private static String stripHeader(String t) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^===\\s*(.*?)\\s*===$").matcher(t);
        return m.matches() ? m.group(1).toUpperCase() : t;
    }

    /** Short firmware token from the build display string, e.g. "S931BXXU1AYB2"
     *  - everything that is not the model-prefixed version is dropped. */
    private static String fwToken() {
        String d = android.os.Build.DISPLAY;
        String model = android.os.Build.MODEL == null
                ? "" : android.os.Build.MODEL.replace("SM-", "").trim();
        if (d == null || d.trim().isEmpty()) return "UNKNOWN";
        if (model.isEmpty()) return d.trim();
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("[A-Z0-9]*" + java.util.regex.Pattern.quote(model) + "[A-Z0-9]*")
                .matcher(d);
        return m.find() ? m.group() : d.trim();
    }

    /** Header lines render big, white and bold; the rest is dimmed. */
    private boolean isHeader(String line) {
        return line.equals("SETUP") || line.equals("EXPLOIT") || line.equals("CLEANUP")
                || line.startsWith("EXPLOIT FAILED")
                || line.equals(fwToken());
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
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Version tag flowing right after the header title.
        SpannableString title = new SpannableString("DirtyFrag 1.08");
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

        // KSU modules toggle: marks every installed module disabled/enabled
        // (diabl0w ksud convention: per-module `disable` flag files, honored
        // at next boot). State is read back from the device via su.
        binding.switchModules.setOnCheckedChangeListener((btn, on) -> {
            if (moduleRefresh) return;
            btn.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            applyModuleState(on);
        });
        mExec.execute(this::refreshModuleState);

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
            appendLog(fwToken());
            for (String l : last.split("\n")) {
                String t = stripHeader(l.trim());
                // Skip stale headers, old result lines and duplicate fw lines.
                if (t.isEmpty()
                        || t.equals("LAST RUN")
                        || t.equals("EXPLOIT SUCCESS")
                        || t.equals(fwToken())) {
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
            binding.twoStep.setSeg2(1f, getString(R.string.verified), 0xFFFFFFFF);
   
        } else if (lastFailed) {
            setFailedState();
        }

        binding.btnRun.setOnClickListener(v -> {
            if (running) return;
            // Two-tap confirmation: first tap arms ("Are you sure"), second runs.
            if (!runArmed) {
                runArmed = true;
                v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                binding.btnRun.setText(R.string.are_you_sure);
                return;
            }
            runArmed = false;
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            running = true;
            binding.btnRun.setEnabled(false);
            binding.btnRun.setText(R.string.running);
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
            appendLog(fwToken());
            binding.twoStep.reset();
            setCompactButton(true, false);
            updateLogVisibility();
            mExec.execute(() -> runExploit(false));
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
            ghRow.setText(R.string.github_page);
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
            exText.setText(R.string.expert_mode);
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

            // -- Remove KSU/KSUD row: 3-tap confirm, greyed without root --
            android.widget.LinearLayout rmCol = new android.widget.LinearLayout(this);
            rmCol.setOrientation(android.widget.LinearLayout.VERTICAL);
            rmCol.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            rmCol.setPadding((int) (20 * md), 0, (int) (20 * md), 0);
            TextView rmTitle = new TextView(this);
            rmCol.setBackgroundResource(R.drawable.menu_row_highlight);
            rmTitle.setText(R.string.remove_ksu);
            rmTitle.setGravity(android.view.Gravity.START);
            rmTitle.setTextColor(rootedMenu ? 0xFFE8E8E8 : 0xFF6E6E6E);
            rmTitle.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            rmCol.addView(rmTitle);
            TextView rmSub = new TextView(this);
            rmSub.setText(rootedMenu? R.string.click_3_times: R.string.requires_root);
            rmSub.setGravity(android.view.Gravity.START);
            rmSub.setTextColor(rootedMenu ? 0xFF8E8E8E : 0xFF5A5A5A);
            rmSub.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 11);
            rmCol.addView(rmSub);
            final int[] taps = {0};
            rmCol.setOnClickListener(v2 -> {
                if (!rootedMenu) return;
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                taps[0]++;
                if (taps[0] == 1) {
                    rmTitle.setText(R.string.are_you_sure);
		    rmSub.setText(R.string.click_2_times);
                    return;
                }
                if (taps[0] == 2) {
                    rmTitle.setText(R.string.one_more_click);
		    rmSub.setText(R.string.click_1_time);
                    return;
                }
                if (pwRef[0] != null) pwRef[0].dismiss();
                try {
                    // Deliberately NOT calling `ksud uninstall`: its upstream
                    // implementation force-flashes a stored boot image when a
                    // backup exists and reboots the device after 5 seconds -
                    // surprises we don't want. Explicit removals only, plus
                    // the manager app this row promises to remove.
                    Process p = Runtime.getRuntime().exec(new String[]{
                            "su", "-c",
                            "rm -rf /data/adb/ksu /data/adb/ksud"
                                    + " /data/adb/post-fs-data.d"
                                    + " /data/adb/modules_update"
                                    + " /data/adb/modules /data/adb/ksu.bk"
                                    + " /data/adb/preinit*; "
                                    + "pm uninstall me.weishu.kernelsu; "
                                    + "rm -f /data/user_de/0/df.root/ksud"});
                    int rc = p.waitFor();
                    mMain.post(() -> {
                      Toast.makeText(MainActivity.this, rc == 0 ? getString(R.string.ksu_removed) : getString(R.string.removal_failed, rc), Toast.LENGTH_SHORT).show();                    });
                } catch (Exception e) {
                    Toast.makeText(MainActivity.this, R.string.su_not_available, Toast.LENGTH_SHORT).show();
                }
            });
            box.addView(rmCol, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (58 * md)));
                       // -- import ksud Page row --
            if (isXiaomiFamily()) {
    TextView ksudRow = new TextView(this);
    ksudRow.setBackgroundResource(R.drawable.menu_row_highlight);
    ksudRow.setText(R.string.import_ksud);
    ksudRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
    ksudRow.setPadding((int) (20 * md), 0, 0, 0);
    ksudRow.setTextColor(0xFFE8E8E8);
    ksudRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
    ksudRow.setOnClickListener(v2 -> {
        v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
        if (pwRef[0] != null) pwRef[0].dismiss();
        ksudPicker.launch("*/*");
    });
    box.addView(ksudRow, new android.widget.LinearLayout.LayoutParams(android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));
}
if (isXiaomiFamily()) {
    TextView forceRow = new TextView(this);
    forceRow.setBackgroundResource(R.drawable.menu_row_highlight);
    forceRow.setText(R.string.force_jailbreak);
    forceRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
    forceRow.setPadding((int) (20 * md), 0, 0, 0);
    forceRow.setTextColor(0xFFE8E8E8);
    forceRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);

    forceRow.setOnClickListener(v2 -> {
        v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
        if (pwRef[0] != null) pwRef[0].dismiss();
        forceXiaomiJailbreak();
    });

    box.addView(forceRow, new android.widget.LinearLayout.LayoutParams(
            android.view.ViewGroup.LayoutParams.MATCH_PARENT,
            (int) (46 * md)));
}

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
    }

    /** Expert mode off: the autorun card is inaccessible - greyed text and
     *  disabled toggles, titles suffixed with (Expert). */
    private void applyExpertMode() {
        boolean ok = expertMode;
        binding.tvAutorunTitle.setText(ok ? R.string.autorun : R.string.autorun_expert);
        binding.tvRebootTitle.setText(ok ? R.string.auto_reboot : R.string.auto_reboot_expert);
        binding.tvAutorunTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvAutorunDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.tvRebootTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvRebootDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.switchBootStart.setEnabled(ok);
        binding.switchAutoSoftReboot.setEnabled(ok
                && binding.switchBootStart.isChecked());
    }

    /** Re-read the modules state when returning to the app: if the user just
     *  granted root in the KSU manager, the toggle updates immediately
     *  instead of staying stale until the next app open. */
    @Override
    protected void onResume() {
        super.onResume();
        mExec.execute(this::refreshModuleState);
    }

    private void setRootedState() {
        setRootedState(true);
    }

    /** Runs a command as root (su). Returns stdout, or null when su is
     *  unavailable (module not loaded / not granted). Sets suState with the
     *  failure reason for the UI. */
    private String suState = "unknown";
    private String runSu(String cmd) {
        suState = "unknown";
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            java.io.BufferedReader err = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getErrorStream()));
            StringBuilder sb = new StringBuilder();
            String ln;
            while ((ln = r.readLine()) != null) sb.append(ln).append('\n');
            StringBuilder eb = new StringBuilder();
            while ((ln = err.readLine()) != null) eb.append(ln).append('\n');
            err.close();
            r.close();
            int rc = p.waitFor();
            if (rc == 0) {
                suState = "ok";
                return sb.toString();
            }
            suState = ("denied (rc " + rc + ")" + (eb.length() > 0 ? ": " + eb.toString().trim() : ""));
            Log.i(TAG, "su probe failed: " + suState);
            return null;
        } catch (Exception e) {
            suState = "not found";
            return null;
        }
    }

    /** Reads the modules' disable-flag state from /data/adb/modules via su and
     *  syncs the toggle. All-disabled = switch off, otherwise on. */
    private void refreshModuleState() {
        String mods = runSu("ls /data/adb/modules 2>/dev/null");
        if (mods == null) {
            mMain.post(() -> {
                moduleRefresh = true;
                binding.switchModules.setChecked(false);
                binding.switchModules.setEnabled(false);
                moduleRefresh = false;
                binding.modulesSubtitle.setText("not found".equals(suState) ? getString(R.string.modules_require_root) : 		        getString(R.string.no_modules));
            });
            return;
        }
        int total = 0;
        for (String s : mods.split("\n")) if (!s.trim().isEmpty()) total++;
        if (total == 0) {
            mMain.post(() -> {
                moduleRefresh = true;
                binding.switchModules.setChecked(false);
                binding.switchModules.setEnabled(false);
                moduleRefresh = false;
                Log.i(TAG, "modules toggle: no modules installed");
                binding.modulesSubtitle.setText(R.string.no_modules);
            });
            return;
        }
        String dis = runSu("ls /data/adb/modules/*/disable 2>/dev/null");
        int disabled = 0;
        if (dis != null) for (String s : dis.split("\n")) if (!s.trim().isEmpty()) disabled++;
        boolean allDisabled = disabled >= total;
        final int fTotal = total, fDisabled = Math.min(disabled, total);
        String text = fDisabled == 0
                ? getString(R.string.modules_enabled_next_reroot)
                : fDisabled == fTotal ? getString(R.string.modules_disabled_next_reroot)
                    : getString(R.string.modules_disabled_count_next_reroot, fDisabled, fTotal);
        Log.i(TAG, "modules toggle: " + fDisabled + "/" + fTotal + " disabled -> " + text);
        mMain.post(() -> {
            moduleRefresh = true;
            binding.switchModules.setChecked(!allDisabled);
            binding.switchModules.setEnabled(true);
            moduleRefresh = false;
            binding.modulesSubtitle.setText(text);
        });
    }

    /** Applies the toggle: disable = touch a `disable` flag in every module,
     *  enable = remove them. Takes effect at the next reboot (modules are
     *  mounted during boot only). */
    private void applyModuleState(boolean on) {
        String cmd = on
                ? "rm -f /data/adb/modules/*/disable 2>/dev/null"
                : "for d in /data/adb/modules/*/; do [ -f \"$d/module.prop\" ] && touch \"$d/disable\" 2>/dev/null; done";
        mExec.execute(() -> {
            String r = runSu(cmd);
            mMain.post(() -> {
                Toast.makeText(MainActivity.this,
                        r == null ? getString(R.string.su_not_available)
                                : on ? getString(R.string.ksu_modules_enabled_after_reboot)
                                : getString(R.string.ksu_modules_disabled_after_reboot),
                        Toast.LENGTH_SHORT).show();
                refreshModuleState();
            });
        });
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
        binding.twoStep.setFailed(true);
        binding.twoStep.setSeg1(seg1, getString(R.string.failure));
        binding.twoStep.setSeg2(1f, getString(R.string.reboot), 0xFFE57373);
        binding.btnRun.setEnabled(false);
        binding.btnRun.setText(R.string.run_exploit);
        binding.btnRun.setTextColor(0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
        setCompactButton(false, false);
    }

    private void setRootedState(boolean rooted) {
        runArmed = false;
        binding.btnRun.setEnabled(!rooted);
	binding.btnRun.setText(rooted ? R.string.rooted : R.string.run_exploit);
        binding.btnRun.setTextColor(
                rooted ? 0xFF6E6E6E : 0xFFE0E0E0);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(
                rooted ? 0xFF1F1F1F : 0xFF7A7A7A));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(
                        rooted ? 0xFF1F1F1F : 0xFFA6A6A6));
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
        float target = 0.48f;
        if (compact) {
            float parentW = ((View) binding.btnRun.getParent()).getWidth();
            if (parentW <= 0) parentW = getResources().getDisplayMetrics().widthPixels;
            float density = getResources().getDisplayMetrics().density;
            float extrasPx = (12f + 54f) * density;
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
        binding.btnKsu.setEnabled(ksuLit);
        boolean wasVisible = binding.btnKsu.getVisibility() == View.VISIBLE
                && binding.btnKsu.getAlpha() > 0.99f;
        binding.btnKsu.setBackgroundTintList(ColorStateList.valueOf(
                ksuLit ? 0xFFB0B0B0 : 0xFF1F1F1F));
        binding.btnKsu.setImageResource(R.drawable.ksu_logo);
        if (compact && !wasVisible) {
            // First appearance: pop in quickly.
            binding.btnKsu.setVisibility(View.VISIBLE);
            binding.btnKsu.setAlpha(0f);
            binding.btnKsu.setScaleX(0.6f);
            binding.btnKsu.setScaleY(0.6f);
            binding.btnKsu.postDelayed(() -> binding.btnKsu.animate()
                    .alpha(1f).scaleX(1f).scaleY(1f).setDuration(180)
                    .withEndAction(() -> settleKsuTint(ksuLit)).start(), 150);
        } else if (compact) {
            // Already visible (state change): stay in place, just recolor.
            settleKsuTint(ksuLit);
        } else {
            binding.btnKsu.animate().alpha(0f).scaleX(0.6f).scaleY(0.6f)
                    .setDuration(200)
                    .withEndAction(() -> binding.btnKsu.setVisibility(View.GONE))
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
private boolean isXiaomiFamily() {
    String manufacturer = android.os.Build.MANUFACTURER == null ? "" : android.os.Build.MANUFACTURER.trim().toUpperCase(java.util.Locale.ROOT);
    return manufacturer.equals("XIAOMI") || manufacturer.equals("Xiaomi") || manufacturer.equals("REDMI")|| manufacturer.equals("Redmi")|| manufacturer.equals("POCO");
}

private void forceXiaomiJailbreak() {
    if (!isXiaomiFamily() || running) return;

    running = true;

    binding.outputView.setText("");
    logBuffer.setLength(0);
    if (lastLogFile != null && lastLogFile.exists()) lastLogFile.delete();
    appendLog(fwToken());
    updateLogVisibility();

    mExec.execute(() -> {
        try {
            ExploitRunner.stageKsud(MainActivity.this, MainActivity.this);

            File base = createDeviceProtectedStorageContext().getFilesDir().getParentFile();
            File ksud = new File(base, "ksud");
            File ksudLog = new File(base, "ksulog.txt");

            if (ksudLog.exists()) ksudLog.delete();

            report("\n=== force jailbreak ===\n");
            report("manufacturer: " + android.os.Build.MANUFACTURER + "\n");
            report("ksud: " + ksud.getAbsolutePath() + "\n");

            Process p = new ProcessBuilder(
                    "/system/bin/service",
                    "call",
                    "miui.mqsas.IMQSNative",
                    "21",
                    "i32", "1",
                    "s16", ksud.getAbsolutePath(),
                    "i32", "1",
                    "s16", "late-load",
                    "s16", ksudLog.getAbsolutePath(),
                    "i32", "60"
            ).redirectErrorStream(true).start();

            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));

            StringBuilder serviceOutput = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                serviceOutput.append(line).append('\n');
            }

            reader.close();

            int rc = p.waitFor();

            if (serviceOutput.length() > 0) {
                report(serviceOutput.toString());
            }

            for (int i = 0; i < 20 && (!ksudLog.exists() || ksudLog.length() == 0); i++) {
                Thread.sleep(250);
            }

            if (ksudLog.exists() && ksudLog.length() > 0) {
                try (java.io.FileInputStream in = new java.io.FileInputStream(ksudLog);
                     java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {

                    byte[] buf = new byte[8192];
                    int n;

                    while ((n = in.read(buf)) != -1) {
                        out.write(buf, 0, n);
                    }

                    String log = out.toString(java.nio.charset.StandardCharsets.UTF_8.name());

                    if (!log.trim().isEmpty()) {
                        report("\n=== ksud log ===\n");
                        report(log + "\n");
                    }
                }
            }

            report("service call rc=" + rc + "\n");

            mMain.post(() -> {
                running = false;
                Toast.makeText(MainActivity.this,
                        rc == 0 ? R.string.force_jailbreak_done : R.string.force_jailbreak_failed,
                        Toast.LENGTH_SHORT).show();
                updateLogVisibility();
                mExec.execute(this::refreshModuleState);
            });

        } catch (Exception e) {
            Log.e(TAG, "force jailbreak failed", e);
            report("\nforce jailbreak failed: " + e + "\n");

            mMain.post(() -> {
                running = false;
                Toast.makeText(MainActivity.this,
                        R.string.force_jailbreak_failed,
                        Toast.LENGTH_SHORT).show();
                updateLogVisibility();
            });
        }
    });
}
    private void copyKsud(Uri uri) {
    mExec.execute(() -> {
        File base = createDeviceProtectedStorageContext()
                .getFilesDir()
                .getParentFile();

        File dest = new File(base, "ksud");
        File tmp = new File(base, "ksud.import.tmp");

        try {
            if (tmp.exists()) {
                tmp.delete();
            }

            
            try (java.io.InputStream in =
                         getContentResolver().openInputStream(uri);
                 java.io.OutputStream out =
                         new FileOutputStream(tmp, false)) {

                if (in == null) {
                    throw new IOException("Cannot open file");
                }

                byte[] buf = new byte[8192];
                int n;

                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            }

            if (!tmp.setExecutable(true, false)) {
                throw new IOException("chmod failed");
            }

            // 驗證 ksud --version
            Process p = new ProcessBuilder(
                    tmp.getAbsolutePath(),
                    "--version"
            )
                    .redirectErrorStream(true)
                    .start();

            boolean finished = p.waitFor(
                    5,
                    java.util.concurrent.TimeUnit.SECONDS
            );

            if (!finished) {
                p.destroyForcibly();
                throw new IOException("ksud version timeout");
            }

            java.io.BufferedReader reader =
                    new java.io.BufferedReader(
                            new java.io.InputStreamReader(
                                    p.getInputStream()));

            StringBuilder output = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }

            String version = output.toString().trim();

            if (p.exitValue() != 0) {
                throw new IOException(
                        "ksud --version failed, code "
                                + p.exitValue());
            }

            if (version.isEmpty()) {
                throw new IOException(
                        "ksud returned empty version");
            }

            // 驗證成功才覆蓋正式 ksud
            if (dest.exists() && !dest.delete()) {
                throw new IOException(
                        "Cannot replace old ksud");
            }

            if (!tmp.renameTo(dest)) {
                throw new IOException(
                        "Cannot install ksud");
            }

            if (!dest.setExecutable(true, false)) {
                throw new IOException(
                        "chmod final ksud failed");
            }

            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit()
                    .putBoolean("custom_ksud", true)
                    .apply();

            mMain.post(() ->
                    Toast.makeText(
                            MainActivity.this,
                            "KSUD imported\n" + version,
                            Toast.LENGTH_LONG
                    ).show());

        } catch (Exception e) {
            Log.e(TAG, "copy ksud failed", e);

            if (tmp.exists()) {
                tmp.delete();
            }

            mMain.post(() ->
                    Toast.makeText(
                            MainActivity.this,
                            "Invalid KSUD: " + e.getMessage(),
                            Toast.LENGTH_LONG
                    ).show());
        }
    });
}
    private void openKsu() {
        // Try the known manager packages: official KernelSU, KernelSU-Next, APatch.
        String[] candidates = {
                "me.weishu.kernelsu", "com.rifsxd.ksunext", "me.bmax.apatch"};
        PackageManager pm = getPackageManager();
        for (String pkg : candidates) {
            Intent launch = pm.getLaunchIntentForPackage(pkg);
            if (launch != null) {
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(launch);
                return;
            }
        }
        Toast.makeText(this, R.string.ksu_manager_not_found, Toast.LENGTH_SHORT).show();
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

    private void runExploit(boolean softReboot) {
        try {
            int rc = ExploitRunner.run(this, this, softReboot);
            if (rc != 0) {
                String why = rc == 1 ? "ksud exited with error" : "check logs";
                report("\n=== exploit failed: " + why + " ===\n");
            }
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
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
                    binding.twoStep.setSeg2(1f,getString(R.string.verified),0xFFFFFFFF
    );
                } else {
                    setRootedState(false);
                    setFailedState();
                }
                updateLogVisibility();
            });
        }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            Toast.makeText(this, R.string.no_browser, Toast.LENGTH_SHORT).show();
        }
    }

}
