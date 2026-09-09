package dev.indevelopment.m3qroot;

import android.content.Intent;
import android.content.pm.PackageInfo;
 import android.graphics.Typeface;
 import android.content.SharedPreferences;
 import android.content.pm.PackageManager;
import android.graphics.Insets;
import android.os.Build;
 import android.util.TypedValue;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
   import android.text.Html;
import android.text.SpannableString;
import android.text.Spanned;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.window.OnBackInvokedDispatcher;
 import android.widget.LinearLayout;
 import android.widget.TextView;
 import android.text.method.ScrollingMovementMethod;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
 import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.ArrayList;
 import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

import rikka.shizuku.Shizuku;

public final class MainActivity extends AppCompatActivity {
    private static final int SHIZUKU_PERMISSION_REQUEST = 0x4d33;
    private static final long HOLD_TO_CONFIRM_MILLIS = 1400L;
    private static final String KSU_MANAGER_PACKAGE = "me.weishu.kernelsu";
    private static final int STATUS_SUCCESS = 0xff18753c;
    private static final int STATUS_WORKING = 0xff9a6700;
    private static final int STATUS_WARNING = 0xffb3261e;
    private static final int STATUS_NEUTRAL = 0xff5f6b76;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicBoolean shizukuPermissionPending = new AtomicBoolean();
    private final Shizuku.OnRequestPermissionResultListener shizukuPermissionListener =
            (requestCode, grantResult) -> {
                if (requestCode != SHIZUKU_PERMISSION_REQUEST) return;
                if (!shizukuPermissionPending.compareAndSet(true, false)) return;
                ui.post(() -> {
                    if (grantResult == PackageManager.PERMISSION_GRANTED) {
                        append("Shizuku shell permission granted");
                        beginExploit(true);
                    } else {
                        abortPendingRun("Shizuku permission denied; nothing was run.");
                    }
                });
            };

    private M3qRootEngine engine;
    private MaterialCardView statusCard;
    private MaterialCardView diagnosticsCard;
    private TextView status;
    private TextView statusDetail;
    private TextView dashboard;
    private android.view.View statusTile;
    private android.widget.ImageView statusIcon;
    private MaterialButton payloadButton;
    private TextView subtitleText;
    private TextView versionChip;
    private TextView updateChip;
    private TextView log;
    private MaterialButton run;
    private MaterialButton reapplyModules;
    private MaterialButton restartZygote;
    private MaterialButton statusRefresh;
    private MaterialButton unrootReboot;
    private MaterialButton diagnosticsToggle;
    private boolean diagnosticsVisible;
    private boolean runIsReboot;
    private volatile String activePayloadId = PayloadStore.BUNDLED_PAYLOAD_ID;
    private volatile boolean payloadResolved;
    private volatile java.util.List<PayloadStore.Profile> lastRegistry;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Shizuku.addRequestPermissionResultListener(shizukuPermissionListener);
        getWindow().setDecorFitsSystemWindows(false);
        setContentView(R.layout.activity_main);
        applySystemBarInsets(findViewById(R.id.page_scroll));
        bindViews();
        bindActions();
        getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                OnBackInvokedDispatcher.PRIORITY_DEFAULT, () -> {
                    if (running.get()) {
                        append("The app cannot be closed until the kernel work finishes.");
                    } else {
                        finish();
                    }
                });

        engine = new M3qRootEngine(this, new M3qRootEngine.Listener() {
            @Override
            public void onStatus(String text, int color) {
                setStatus(text, color);
            }

            @Override
            public void onLog(String line) {
                append(line);
            }
        });

        append("==== device diagnostics ====");
        append("Model: " + Build.MODEL);
        append("Kernel: " + System.getProperty("os.version", "unknown"));
        append("Firmware: " + Build.FINGERPRINT);

        if (!deviceSupported()) {
            setStatus("Checking device", STATUS_WORKING);
            setStatusDetail("Verifying firmware and payload compatibility.");
            run.setEnabled(false);
            append("Bundled payloads target Galaxy S25 (S931BXXUCZZI4), Galaxy S25+ (S936BXXUCZZI4) and Galaxy S25 Ultra (S938BXXUCZZI4), all One UI 9 beta 2; other devices can pick a matching payload.");
        } else {
            setStatus(getString(R.string.status_checking), STATUS_WORKING);
            setStatusDetail(getString(R.string.status_checking_detail));
        }
    }

    private void bindViews() {
        statusCard = findViewById(R.id.status_card);
        diagnosticsCard = findViewById(R.id.diagnostics_card);
        status = findViewById(R.id.status);
        statusDetail = findViewById(R.id.status_detail);
        dashboard = findViewById(R.id.dashboard);
        statusTile = findViewById(R.id.status_tile);
        statusIcon = findViewById(R.id.status_icon);
        statusTile.setClickable(true);
        bindHoldAction(statusTile, "KernelSU manager", 1000L,
                () -> openPackage(KSU_MANAGER_PACKAGE,
                        "Grant SU to SamSU and refresh."));
        payloadButton = findViewById(R.id.payload_button);
        subtitleText = findViewById(R.id.app_subtitle);
        subtitleText.setText(deviceMarketingLabel());
        versionChip = findViewById(R.id.version_chip);
        updateChip = findViewById(R.id.update_chip);
        versionChip.setText(appVersion());
        updateChip.setOnClickListener(v -> {
            try {
                startActivity(new android.content.Intent(
                        android.content.Intent.ACTION_VIEW,
                        android.net.Uri.parse("https://github.com/mitschud/samsu/releases")));
            } catch (Exception ignored) {
                /* No browser on device — leave the pill non-functional rather than crash. */
            }
        });
        worker.execute(this::checkForAppUpdate);
        log = findViewById(R.id.log);
        log.setMovementMethod(new ScrollingMovementMethod());
        run = findViewById(R.id.run);
        reapplyModules = findViewById(R.id.reapply_modules);
        restartZygote = findViewById(R.id.restart_zygote);
        statusRefresh = findViewById(R.id.status_refresh);
        unrootReboot = findViewById(R.id.unroot_reboot);
        diagnosticsToggle = findViewById(R.id.diagnostics_toggle);
    }

    private static String deviceMarketingLabel() {
        String model = Build.MODEL == null ? "" : Build.MODEL.trim();
        String family = deviceFamilyName(model);
        return family.equals(model) ? model : family + " \u00b7 " + model;
    }

    private static String deviceFamilyName(String model) {
        String upper = model.toUpperCase(Locale.US);
        if (upper.startsWith("SM-S931")) return "Galaxy S25";
        if (upper.startsWith("SM-S936")) return "Galaxy S25+";
        if (upper.startsWith("SM-S938")) return "Galaxy S25 Ultra";
        if (upper.startsWith("SM-S937")) return "Galaxy S25 Edge";
        if (upper.startsWith("SM-F966")) return "Galaxy Z Fold 7";
        if (upper.startsWith("SM-F761")) return "Galaxy Z Flip 7";
        return model;
    }

    private static void applySystemBarInsets(View view) {
        int left = view.getPaddingLeft();
        int top = view.getPaddingTop();
        int right = view.getPaddingRight();
        int bottom = view.getPaddingBottom();
        view.setOnApplyWindowInsetsListener((target, windowInsets) -> {
            Insets bars = windowInsets.getInsets(
                    WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            target.setPadding(left + bars.left, top + bars.top,
                    right + bars.right, bottom + bars.bottom);
            return windowInsets;
        });
        view.requestApplyInsets();
    }

    private void bindActions() {
        bindHoldAction(run, "Root", 700L, this::onRunHoldAction);
        bindHoldAction(reapplyModules, "Module reload", HOLD_TO_CONFIRM_MILLIS, this::startModuleReload);
        bindHoldAction(restartZygote, "Soft reboot", HOLD_TO_CONFIRM_MILLIS, this::startSoftBoot);
        bindHoldAction(unrootReboot, "Unroot", HOLD_TO_CONFIRM_MILLIS, this::startUnrootReboot);
        statusRefresh.setOnClickListener(v -> worker.execute(this::refreshRootState));
        diagnosticsToggle.setOnClickListener(v -> toggleDiagnostics());
        findViewById(R.id.export_log).setOnClickListener(v -> exportLastLog());
        payloadButton.setOnClickListener(v -> showPayloadDialog());
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (engine != null && !running.get()) {
            worker.execute(() -> {
            resolvePayload();
            refreshRootState();
        });
        }
    }

    private void onRunHoldAction() {
        if (runIsReboot) {
            startRebootOnFail();
        } else {
            onRunClicked();
        }
    }

    private volatile PayloadStore.Profile activeProfile;
    private volatile boolean payloadDownloading;

    /** Bundled-target check, relaxed when a registry payload matches this device. */
    private boolean deviceSupported() {
        if (engine.isSupported()) return true;
        PayloadStore.Profile profile = activeProfile;
        return profile != null
                && profile.models.contains(PayloadStore.deviceModel());
    }

    private void resolvePayload() {
        if (payloadResolved) return;
        payloadResolved = true;
        SharedPreferences prefs = getSharedPreferences("samsu_payload", MODE_PRIVATE);
        String manualId = prefs.getString("manual_payload_id", "");
        List<PayloadStore.Profile> registry;
        try {
            registry = PayloadStore.fetchRegistry();
            lastRegistry = registry;
        } catch (Exception error) {
            append("Payload registry unavailable: " + error.getMessage());
            useBundledPayload(manualId);
            return;
        }

        PayloadStore.Profile match = null;
        boolean kernelMismatch = false;
        if (!manualId.isEmpty()) {
            match = PayloadStore.findById(registry, manualId);
            if (match == null && PayloadStore.isBundledId(manualId)) {
                append("Using bundled payload (manual selection).");
                activePayloadId = manualId;
                activeProfile = null;
                engine.setPayloadOverride(null);
                engine.setBundledPayloadLib(PayloadStore.bundledLibName(manualId));
                engine.setKsudOverride(null, -1);
                engine.setKmiOverride(null);
                return;
            }
            if (match != null) {
                kernelMismatch = !PayloadStore.kernelMatches(match);
                if (kernelMismatch) {
                    append("WARNING: manually selected payload " + match.payloadId
                            + " targets a different kernel; trying anyway.");
                }
            }
        }
        if (match == null) {
            match = PayloadStore.matchRemote(registry);
        }
        if (match == null) {
            String bundledId = PayloadStore.bundledPayloadIdForDevice();
            append("No remote payload matches this device; using bundled "
                    + bundledId + ".");
            activePayloadId = bundledId;
            activeProfile = null;
            engine.setPayloadOverride(null);
            engine.setBundledPayloadLib(PayloadStore.bundledLibName(bundledId));
            engine.setKsudOverride(null, -1);
            engine.setKmiOverride(null);
            return;
        }
        if (kernelMismatch) {
            append("WARNING: kernel version differs from the payload target; "
                    + "attempting anyway.");
        }
        File cached = PayloadStore.cachedPayload(this, match.payloadId);
        boolean exploitFresh = cached.isFile()
                && (match.exploitSize <= 0 || cached.length() == match.exploitSize);
        if (exploitFresh) {
            activePayloadId = match.payloadId;
            activeProfile = match;
            engine.setPayloadOverride(cached);
            applyRegistryKsud(match);
            append("Using cached payload " + match.payloadId + ".");
            return;
        }
        if (cached.isFile()) {
            append("Cached payload " + match.payloadId + " is stale ("
                    + cached.length() + " bytes, expected "
                    + match.exploitSize + "); re-downloading.");
            cached.delete();
        }
        append("Downloading payload " + match.payloadId + " ...");
        payloadDownloading = true;
        ui.post(() -> payloadButton.setText(buildPayloadButtonLabel()));
        try {
            File file = PayloadStore.downloadExploit(this, match);
            activePayloadId = match.payloadId;
            activeProfile = match;
            engine.setPayloadOverride(file);
            applyRegistryKsud(match);
            append("Payload downloaded: " + file.getName()
                    + " (" + file.length() + " bytes)");
        } catch (Exception error) {
            String bundledId = PayloadStore.bundledPayloadIdForDevice();
            append("Payload download failed: " + error.getMessage());
            append("Using bundled payload " + bundledId + ".");
            activePayloadId = bundledId;
            activeProfile = null;
            engine.setPayloadOverride(null);
            engine.setBundledPayloadLib(PayloadStore.bundledLibName(bundledId));
            engine.setKsudOverride(null, -1);
            engine.setKmiOverride(null);
        } finally {
            payloadDownloading = false;
            ui.post(() -> payloadButton.setText(buildPayloadButtonLabel()));
        }
    }

    /** Registry payloads ship their own KSU build; stage it for late-load. */
    private void applyRegistryKsud(PayloadStore.Profile match) {
        if (match.ksudUrl == null || match.ksudUrl.isEmpty()) {
            engine.setKsudOverride(null, -1);
            engine.setKmiOverride(null);
            return;
        }
        File cachedKsud = PayloadStore.cachedKsud(this, match.payloadId);
        boolean ksudFresh = cachedKsud.isFile()
                && (match.ksudSize <= 0 || cachedKsud.length() == match.ksudSize);
        if (!ksudFresh) {
            if (cachedKsud.isFile()) {
                append("Cached KernelSU daemon " + match.payloadId
                        + " is stale (" + cachedKsud.length() + " bytes, expected "
                        + match.ksudSize + "); re-downloading.");
                cachedKsud.delete();
            }
            append("Downloading KernelSU daemon " + match.payloadId + " ...");
            payloadDownloading = true;
            ui.post(() -> payloadButton.setText(buildPayloadButtonLabel()));
            try {
                cachedKsud = PayloadStore.downloadKsud(this, match);
            } catch (Exception error) {
                append("KernelSU daemon download failed: " + error.getMessage()
                        + "; using bundled KSU module.");
                payloadDownloading = false;
                ui.post(() -> payloadButton.setText(buildPayloadButtonLabel()));
                engine.setKsudOverride(null, -1);
                engine.setKmiOverride(null);
                return;
            }
            payloadDownloading = false;
            ui.post(() -> payloadButton.setText(buildPayloadButtonLabel()));
            append("KernelSU daemon downloaded: " + cachedKsud.getName()
                    + " (" + cachedKsud.length() + " bytes)");
        } else {
            append("Using cached KernelSU daemon " + match.payloadId + ".");
        }
        engine.setKsudOverride(cachedKsud, match.ksudSize);
        engine.setKmiOverride(match.kmi);
    }

    private void useBundledPayload(String manualId) {
        File cached = manualId.isEmpty()
                ? null : PayloadStore.cachedPayload(this, manualId);
        if (cached != null && cached.isFile()
                && !PayloadStore.isBundledId(manualId)) {
            activePayloadId = manualId;
            activeProfile = new PayloadStore.Profile(manualId, "",
                    java.util.Arrays.asList(PayloadStore.deviceModel()),
                    new java.util.ArrayList<>(), "", -1);
            engine.setPayloadOverride(cached);
            File cachedKsud = PayloadStore.cachedKsud(this, manualId);
            if (cachedKsud.isFile()) {
                engine.setKsudOverride(cachedKsud, -1);
            }
            append("Using cached payload " + manualId + ".");
            return;
        }
        String bundledId = PayloadStore.bundledPayloadIdForDevice();
        append("Using bundled payload " + bundledId + ".");
        activePayloadId = bundledId;
        activeProfile = null;
        engine.setPayloadOverride(null);
        engine.setBundledPayloadLib(PayloadStore.bundledLibName(bundledId));
        engine.setKsudOverride(null, -1);
        engine.setKmiOverride(null);
    }

    private CharSequence buildPayloadButtonLabel() {
        String prefix = "Payload selected : ";
        String value = activePayloadId;

        if (payloadDownloading) {
            value = "Downloading";
        } else if (!deviceSupported()) {
            prefix = "Payload : ";
            value = "none for this device";
        }

        SpannableString label = new SpannableString(prefix + value);
        label.setSpan(new android.text.style.AbsoluteSizeSpan(12, true), 0,
                prefix.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        label.setSpan(new android.text.style.AbsoluteSizeSpan(10, true),
                prefix.length(), label.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return label;
    }
    private void showPayloadDialog() {
        List<PayloadStore.Profile> registry = lastRegistry;
        if (registry == null) {
            append("Fetching payload registry for selection ...");
            worker.execute(() -> {
                try {
                    lastRegistry = PayloadStore.fetchRegistry();
                } catch (Exception error) {
                    append("Payload registry unavailable: " + error.getMessage());
                    return;
                }
                ui.post(this::showPayloadDialog);
            });
            return;
        }
        SharedPreferences prefs = getSharedPreferences("samsu_payload", MODE_PRIVATE);
        String manualId = prefs.getString("manual_payload_id", "");
        String model = PayloadStore.deviceModel();
        List<PayloadStore.Profile> options = new ArrayList<>();
        String deviceBundled = PayloadStore.bundledPayloadIdForDevice();
        options.add(PayloadStore.bundledProfile(deviceBundled));
        List<PayloadStore.Profile> deviceMatches = new ArrayList<>();
        for (PayloadStore.Profile profile : registry) {
            if (!PayloadStore.isBundledId(profile.payloadId)
                    && profile.models.contains(model)) {
                deviceMatches.add(profile);
            }
        }
        deviceMatches.sort((a, b) -> Boolean.compare(
                PayloadStore.kernelMatches(b), PayloadStore.kernelMatches(a)));
        for (PayloadStore.Profile profile : deviceMatches) {
            if (options.size() >= 5) break;
            options.add(profile);
        }
                float density = getResources().getDisplayMetrics().density;
        LinearLayout list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (12 * density);
        list.setPadding(pad, pad / 2, pad, pad / 2);
        TextView dialogTitle = new TextView(this);
        dialogTitle.setText("Select payload");
        dialogTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 17);
        dialogTitle.setTypeface(null, Typeface.BOLD);
        dialogTitle.setTextColor(0xFFEDEDED);
        int titlePad = (int) (14 * density);
        dialogTitle.setPadding(titlePad, titlePad, titlePad, (int) (4 * density));
        list.addView(dialogTitle, 0);
        TextView holdHint = new TextView(this);
        holdHint.setText("Hold payload to remove it from cache");
        holdHint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        holdHint.setTextColor(0xFF8A8A8A);
        holdHint.setPadding(titlePad, 0, titlePad, (int) (6 * density));
        list.addView(holdHint, 1);
        LinearLayout rowsBox = new LinearLayout(this);
        rowsBox.setOrientation(LinearLayout.VERTICAL);
        rowsBox.setPadding(0, 0, 0, (int) (14 * density));
        final int maxRowsHeight = (int) (getResources().getDisplayMetrics().heightPixels * 0.45f);
        android.widget.ScrollView rowsScroll = new android.widget.ScrollView(this) {
            @Override
            protected void onMeasure(int widthSpec, int heightSpec) {
                super.onMeasure(widthSpec, heightSpec);
                if (getMeasuredHeight() > maxRowsHeight) {
                    setMeasuredDimension(getMeasuredWidth(), maxRowsHeight);
                }
            }
        };
        rowsScroll.addView(rowsBox, new LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT));
        list.addView(rowsScroll);
        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(this)
                .setView(list);
        androidx.appcompat.app.AlertDialog dialog = builder.show();
        android.view.Window popupWindow = dialog.getWindow();
        if (popupWindow != null) {
            android.graphics.drawable.GradientDrawable popupBackground =
                    new android.graphics.drawable.GradientDrawable();
            popupBackground.setColor(0xFF141414);
            popupBackground.setCornerRadius(26 * density);
            popupBackground.setStroke((int) (1 * density), 0xFF6E6E6E);
            popupWindow.setBackgroundDrawable(popupBackground);
            android.view.WindowManager.LayoutParams popupParams = popupWindow.getAttributes();
            popupParams.gravity = android.view.Gravity.TOP | android.view.Gravity.CENTER_HORIZONTAL;
            popupParams.y = (int) (210 * getResources().getDisplayMetrics().density);
            popupParams.dimAmount = 0.72f;
            popupParams.flags |= android.view.WindowManager.LayoutParams.FLAG_DIM_BEHIND;
            popupWindow.setAttributes(popupParams);
        }
        for (int index = 0; index < options.size(); index++) {
            PayloadStore.Profile option = options.get(index);
            boolean selected = option.payloadId.equals(
                    manualId.isEmpty()
                        ? PayloadStore.bundledPayloadIdForDevice() : manualId);
            boolean bundled = PayloadStore.isBundledId(option.payloadId);
            boolean downloaded = bundled
                    || PayloadStore.cachedPayload(this, option.payloadId).isFile();
            com.google.android.material.button.MaterialButton row =
                    new com.google.android.material.button.MaterialButton(this,
                            null,
                            com.google.android.material.R.attr.materialButtonOutlinedStyle);
            row.setText((bundled ? "Bundled: " : "")
                    + option.payloadId
                    + (option.displayName.isEmpty() || bundled
                            ? "" : "  -  " + option.displayName)
                    + (bundled || PayloadStore.kernelMatches(option)
                            ? "" : "  (kernel mismatch)"));
            row.setAllCaps(false);
            row.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
            row.setSingleLine(true);
            row.setEllipsize(android.text.TextUtils.TruncateAt.END);
            row.setInsetTop(0);
            row.setInsetBottom(0);
            LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                    (int) (46 * density));
            rowParams.setMargins(0, (int) (2 * density), 0, 0);
            row.setLayoutParams(rowParams);
            if (selected && downloaded) {
                row.setBackgroundTintList(
                        android.content.res.ColorStateList.valueOf(0xFF333333));
                row.setStrokeColor(
                        android.content.res.ColorStateList.valueOf(0xFF6E6E6E));
                row.setTextColor(0xFFFFFFFF);
            } else if (downloaded) {
                row.setBackgroundTintList(
                        android.content.res.ColorStateList.valueOf(0x00000000));
                row.setStrokeColor(
                        android.content.res.ColorStateList.valueOf(0xFF4D4D4D));
                row.setTextColor(0xFFDDDDDD);
            } else {
                row.setBackgroundTintList(
                        android.content.res.ColorStateList.valueOf(0x00000000));
                row.setStrokeColor(
                        android.content.res.ColorStateList.valueOf(0xFF333333));
                row.setTextColor(0x66FFFFFF);
            }
            row.setStrokeWidth((int) (1 * density));
            int padV = (int) (11 * density);
            row.setPadding(pad, padV, pad, padV);
            File cachedPayloadFile =
                    PayloadStore.cachedPayload(this, option.payloadId);
            boolean deletable = !bundled && cachedPayloadFile.isFile();
            final boolean[] holdCompleted = {false};
            final Handler holdHandler = new Handler(Looper.getMainLooper());
            final Runnable[] holdFire = {null};
            rowsBox.addView(row);
            row.setOnTouchListener((v, event) -> {
                if (!deletable) {
                    if (event.getAction() == android.view.MotionEvent.ACTION_UP) {
                        selectPayloadRow(option, prefs, dialog);
                    }
                    return true;
                }
                if (event.getAction() == android.view.MotionEvent.ACTION_DOWN) {
                    holdCompleted[0] = false;
                    holdFire[0] = () -> {
                        holdCompleted[0] = true;
                        buzz();
                        row.animate().alpha(1f).setDuration(150).start();
                        removeCachedPayload(option.payloadId);
                        dialog.dismiss();
                        ui.post(() -> showPayloadDialog());
                    };
                    row.animate().alpha(0.35f).setDuration(1500).start();
                    holdHandler.postDelayed(holdFire[0], 1500);
                    return true;
                }
                if (event.getAction() == android.view.MotionEvent.ACTION_UP
                        || event.getAction() == android.view.MotionEvent.ACTION_CANCEL) {
                    holdHandler.removeCallbacks(holdFire[0]);
                    row.animate().alpha(1f).setDuration(150).start();
                    if (!holdCompleted[0]
                            && event.getAction() == android.view.MotionEvent.ACTION_UP) {
                        selectPayloadRow(option, prefs, dialog);
                    }
                }
                return true;
            });
        }
        dialog.show();
    }

    private void selectPayloadRow(PayloadStore.Profile option,
            SharedPreferences prefs, androidx.appcompat.app.AlertDialog dialog) {
        dialog.dismiss();
        // "" = auto (device default bundled); explicit id for everything else,
        // including the non-default bundled payload.
        String newId = PayloadStore.BUNDLED_PAYLOAD_ID.equals(option.payloadId)
                ? "" : option.payloadId;
        prefs.edit().putString("manual_payload_id", newId).apply();
        payloadResolved = false;
        append("Payload selection: " + option.payloadId);
        worker.execute(() -> {
            resolvePayload();
            refreshRootState();
        });
    }

    private void removeCachedPayload(String payloadId) {
        File exploit = PayloadStore.cachedPayload(this, payloadId);
        File ksud = PayloadStore.cachedKsud(this, payloadId);
        boolean removedExploit = !exploit.isFile() || exploit.delete();
        boolean removedKsud = !ksud.isFile() || ksud.delete();
        append("Removed cached payload " + payloadId
                + (removedExploit && removedKsud ? "." : " (partial)."));
        if (activePayloadId != null && activePayloadId.equals(payloadId)) {
            String bundledId = PayloadStore.bundledPayloadIdForDevice();
            getSharedPreferences("samsu_payload", MODE_PRIVATE)
                    .edit().putString("manual_payload_id", "").apply();
            activePayloadId = bundledId;
            activeProfile = null;
            engine.setPayloadOverride(null);
            engine.setBundledPayloadLib(PayloadStore.bundledLibName(bundledId));
            engine.setKsudOverride(null, -1);
            engine.setKmiOverride(null);
            payloadResolved = false;
            worker.execute(() -> {
                resolvePayload();
                refreshRootState();
            });
        }
    }

    private void toggleDiagnostics() {
        diagnosticsVisible = !diagnosticsVisible;
        diagnosticsCard.setVisibility(diagnosticsVisible ? View.VISIBLE : View.GONE);
        diagnosticsToggle.setText(diagnosticsVisible
                ? R.string.hide_diagnostics : R.string.show_diagnostics);
        if (diagnosticsVisible) {
            scrollLogToBottom();
        }
    }

    private void buzz() {
        try {
            android.os.Vibrator vibrator =
                    (android.os.Vibrator) getSystemService(VIBRATOR_SERVICE);
            if (vibrator == null || !vibrator.hasVibrator()) return;
            if (android.os.Build.VERSION.SDK_INT >= 29) {
                /* Light system tick: short, low-energy, tactile "tk". */
                vibrator.vibrate(android.os.VibrationEffect.createPredefined(
                        android.os.VibrationEffect.EFFECT_TICK));
            } else {
                vibrator.vibrate(android.os.VibrationEffect.createOneShot(
                        20, 80));
            }
        } catch (Exception ignored) {
            /* No vibrator service: holds stay silent, no failure. */
        }
    }

    private void bindHoldAction(View button, String label, long holdMillis, Runnable action) {
        final Handler holdHandler = new Handler(Looper.getMainLooper());
        final AtomicBoolean fired = new AtomicBoolean();
        final Runnable fire = () -> {
            fired.set(true);
            buzz();
            button.animate().alpha(1f).setDuration(150).start();
            append(label + " triggered");
            action.run();
        };
        button.setOnTouchListener((view, event) -> {
            if (!button.isEnabled()) return false;
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    fired.set(false);
                    button.animate().alpha(0.35f).setDuration(holdMillis).start();
                    holdHandler.postDelayed(fire, holdMillis);
                    return true;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    holdHandler.removeCallbacks(fire);
                    if (!fired.get()) {
                        button.animate().alpha(1f).setDuration(150).start();
                        append("Hold " + label.toLowerCase() + " for "
                                + (holdMillis / 1000.0) + " seconds to trigger.");
                    }
                    return true;
                default:
                    return false;
            }
        });
    }

    private void onRunClicked() {
        if (!running.compareAndSet(false, true)) return;
        worker.execute(() -> {
            M3qRootEngine.RootState current = engine.checkRoot(false);
            resolvePayload();
            if (current.terminationUnconfirmed()) {
                finishUnconfirmedRun();
                return;
            }
            if (current.ready()) {
                finishRun(current);
                return;
            }
            if (current.bootstrap()) {
                append("Bootstrap root detected - finishing KernelSU activation without re-running the exploit.");
                setStatus("Activating KernelSU", STATUS_WORKING);
                setStatusDetail("Finalizes KernelSU setup without repeating kernel writes.");
                ui.post(this::lockUiForRun);
                int code = engine.activateKernelSu();
                append("KernelSU activation exit=" + code);
                if (code == M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED) {
                    finishUnconfirmedRun();
                    return;
                }
                finishRun(engine.checkRoot(true));
                return;
            }
            if (engine.hasAttemptedThisBoot()) {
                running.set(false);
                ui.post(() -> {
                    append("Blocked a retry with the same boot ID.");
                    renderRootState(current);
                });
                return;
            }
            running.set(false);
            ui.post(this::startExploit);
        });
    }

    private void startExploit() {
        if (!running.compareAndSet(false, true)) return;
        lockUiForRun();
        append("==== fresh-root start ====");

        if (ShizukuShell.isRunning()) {
            int uid = ShizukuShell.uid();
            append("Shizuku detected: uid=" + uid + " · tracefs fast path");
            if (!ShizukuShell.isGranted()) {
                setStatus("Shizuku permission required", STATUS_WORKING);
                setStatusDetail("Approve the Shizuku permission prompt shown.");
                try {
                    shizukuPermissionPending.set(true);
                    Shizuku.requestPermission(SHIZUKU_PERMISSION_REQUEST);
                } catch (RuntimeException error) {
                    shizukuPermissionPending.set(false);
                    abortPendingRun("Shizuku permission request error: " + error.getMessage());
                }
                return;
            }
            beginExploit(true);
            return;
        }

        append("Shizuku is not running; using the exact-Image physical-P0 fallback route.");
        beginExploit(false);
    }

    private void beginExploit(boolean useShizuku) {
        long settleMillis = M3qRootEngine.bootSettleRemainingMillis();
        if (settleMillis > 0) {
            long settleSeconds = (settleMillis + 999) / 1000;
            abortPendingRun("Right after boot, wait about " + settleSeconds
                    + " seconds and try again. No attempt was consumed this boot.");
            return;
        }
        if (!engine.markAttemptForThisBoot()) {
            abortPendingRun("Boot state unreadable; refused the kernel run.");
            return;
        }
        setStatus("Activating via Shizuku", STATUS_WORKING);
        setStatusDetail(useShizuku
                ? "Checking safety conditions."
                : "Verifies device security state, then applies temporary root.");
        worker.execute(() -> {
            int code = engine.runFreshRoot(useShizuku);
            append("fresh-root exit=" + code);
            if (code == M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED) {
                finishUnconfirmedRun();
                return;
            }
            finishRun(engine.checkRoot(true));
        });
    }

    private void startModuleReload() {
        if (!running.compareAndSet(false, true)) return;
        lockUiForRun();
        setStatus("Reloading KernelSU module", STATUS_WORKING);
        setStatusDetail("Re-running the KernelSU module start step.");
        append("==== KernelSU module reapply start ====");
        worker.execute(() -> {
            M3qRootEngine.RootState state = engine.checkRoot(false);
            if (!state.ready()) {
                append("KernelSU temporary root not active; nothing was run.");
                finishMaintenance(126, state, "", "");
                return;
            }
            int code = engine.reapplyKernelSuModules();
            append("module reapply exit=" + code);
            if (code == M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED) {
                finishUnconfirmedRun();
                return;
            }
            finishMaintenance(code, engine.checkRoot(false),
                    "Module reload complete",
                    "KernelSU module reapplied. Now proceed with the soft boot.");
        });
    }

    private void startSoftBoot() {
        if (!running.compareAndSet(false, true)) return;
        lockUiForRun();
        setStatus("Preparing soft reboot", STATUS_WORKING);
        setStatusDetail("Restarts the Android app runtime (Zygote).");
        append("Requesting a Zygote restart. If it succeeds, this app closes too.");
        worker.execute(() -> {
            M3qRootEngine.RootState state = engine.checkRoot(false);
            if (!state.ready()) {
                append("KernelSU temporary root not active; nothing was run.");
                finishMaintenance(126, state, "", "");
                return;
            }
            int code = engine.restartZygote();
            append("zygote restart exit=" + code);
            if (code == M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED) {
                finishUnconfirmedRun();
                return;
            }
            finishMaintenance(code, engine.checkRoot(false),
                    "Soft reboot requested",
                    "Check active status in the LSPosed manager shortly.");
        });
    }

    private void startUnrootReboot() {
        startRebootFlow("Rebooting to unroot",
                "Device is restarting; root will be cleared.");
    }

    private void startRebootOnFail() {
        startRebootFlow("Rebooting",
                "Device is restarting; boot counter will be cleared.");
    }

    private void startRebootFlow(String workingTitle, String successDetail) {
        if (!running.compareAndSet(false, true)) return;
        lockUiForRun();
        setStatus(workingTitle, STATUS_WORKING);
        setStatusDetail("Device is rebooting.");
        worker.execute(() -> {
            boolean rootReady = engine.checkRoot(false).ready();
            int code;
            String route;
            if (rootReady) {
                route = "KernelSU root shell";
                append("Requesting device reboot via KernelSU root shell.");
                code = engine.rebootDevice();
                if (code != 0 && code != 124) {
                    if (ShizukuShell.isRunning() && ShizukuShell.isGranted()) {
                        append("Root reboot failed (code " + code
                                + "); falling back to the Shizuku shell.");
                        route = "Shizuku shell";
                        code = rebootViaShizuku();
                    }
                }
            } else if (ShizukuShell.isRunning() && ShizukuShell.isGranted()) {
                route = "Shizuku shell";
                append("Requesting device reboot via Shizuku shell.");
                code = rebootViaShizuku();
            } else {
                route = "none";
                code = 159;
                append("No root and Shizuku is not connected; cannot reboot.");
            }
            append("reboot exit=" + code + " via " + route);
            running.set(false);
            final int exitCode = code;
            final String usedRoute = route;
            ui.post(() -> {
                statusRefresh.setEnabled(true);
                if (exitCode == 0 || exitCode == 124) {
                    setStatus("Rebooting", STATUS_SUCCESS);
                    setStatusDetail(successDetail);
                } else if (usedRoute.equals("Shizuku shell")) {
                    renderRootState(engine.checkRoot(false));
                    setStatus("Reboot failed", STATUS_WARNING);
                    setStatusDetail("Reboot refused, Shizuku is not running");
                } else if (usedRoute.equals("none")) {
                    renderRootState(engine.checkRoot(false));
                    setStatus("Reboot failed", STATUS_WARNING);
                    setStatusDetail("No root or Shizuku available to reboot.");
                } else {
                    renderRootState(engine.checkRoot(false));
                    setStatus("Reboot failed", STATUS_WARNING);
                    setStatusDetail("Reboot was refused (code " + exitCode + ").");
                }
            });
        });
    }

    private int rebootViaShizuku() {
        Process process = ShizukuShell.exec(new String[]{"reboot"}, null, null);
        try {
            return process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return 124;
        }
    }
    private void finishMaintenance(int code, M3qRootEngine.RootState state,
                                   String successText, String successDetail) {
        running.set(false);
        ui.post(() -> {
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            statusRefresh.setEnabled(true);
            renderRootState(state);
            if (code == 0) {
                setStatus(successText, STATUS_SUCCESS);
                setStatusDetail(successDetail);
                return;
            }
            String reason = switch (code) {
                case 124 -> "Could not confirm job completion.";
                case 125 -> "KernelSU configuration verification failed.";
                case 126 -> "KernelSU root permission required.";
                default -> "Command failed. code=" + code;
            };
            setStatus("Job failed", STATUS_WARNING);
            setStatusDetail(reason + " Check the status again.");
        });
    }

    private void lockUiForRun() {
        run.setEnabled(false);
        reapplyModules.setEnabled(false);
        restartZygote.setEnabled(false);
            unrootReboot.setEnabled(false);
        statusRefresh.setEnabled(false);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    private void abortPendingRun(String message) {
        append(message);
        running.set(false);
        ui.post(() -> {
            run.setVisibility(View.VISIBLE);
            run.setEnabled(deviceSupported());
            reapplyModules.setEnabled(false);
            restartZygote.setEnabled(false);
            unrootReboot.setEnabled(false);
            statusRefresh.setEnabled(true);
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            setStatus("Wait 180 seconds", STATUS_NEUTRAL);
            setStatusDetail("Device was freshly booted, wait for idle.");
        });
    }

    private void refreshRootState() {
        M3qRootEngine.RootState state = engine.checkRoot(false);
        ui.post(() -> renderRootState(state));
    }

    private void renderRootState(M3qRootEngine.RootState state) {
        runIsReboot = false;
        if (state.terminationUnconfirmed()) {
            run.setVisibility(View.VISIBLE);
            setStatus("Job status unknown", STATUS_WARNING);
            setStatusDetail("For safety, reboot the device and check again.");
            run.setText(R.string.run_reboot_check);
            run.setEnabled(false);
        } else if (state.ready()) {
            setStatus("Rooted", STATUS_SUCCESS);
            setStatusDetail("ADBsu root bridge loaded");
            run.setVisibility(View.GONE);
        } else if (state.bootstrap()) {
            run.setVisibility(View.VISIBLE);
            setStatus("Root ready", STATUS_WORKING);
            setStatusDetail("Only the KernelSU activation step remains.");
            run.setText(R.string.run_kernel_su_activate);
            run.setEnabled(true);
        } else if (engine.hasAttemptedThisBoot()) {
            run.setVisibility(View.VISIBLE);
            setStatus("Failed", STATUS_WARNING);
            setStatusDetail("Kernel panic prevented, reboot required");
            run.setText(R.string.run_reboot_retry);
            runIsReboot = true;
            run.setEnabled(true);
        } else {
            run.setVisibility(View.VISIBLE);
            setStatus("Unrooted", STATUS_NEUTRAL);
            setStatusDetail(deviceSupported()
                    ? "Device verified - Wait 180s after boot"
                    : "Wait 180s after boot");
            run.setText(R.string.root_activate);
            run.setEnabled(deviceSupported());
        }
        boolean ksuOk = ksuManagerVersionOk();
        boolean maintenanceReady = state.ready() && !running.get() && ksuOk;
        reapplyModules.setEnabled(maintenanceReady);
        restartZygote.setEnabled(maintenanceReady);
        unrootReboot.setEnabled(state.ready() && !running.get());
        statusRefresh.setEnabled(!running.get());
        renderDashboard(state);
    }


    private boolean ksuManagerVersionOk() {
        try {
            PackageInfo info = getPackageManager().getPackageInfo(
                    KSU_MANAGER_PACKAGE, PackageManager.PackageInfoFlags.of(0));
            return normalizeKsuVersion(info.versionName).startsWith("3.2.5");
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private String ksuManagerLabel() {
        try {
            PackageInfo info = getPackageManager().getPackageInfo(
                    KSU_MANAGER_PACKAGE, PackageManager.PackageInfoFlags.of(0));
            String version = normalizeKsuVersion(info.versionName);
            return version.startsWith("3.2.5") ? version + " \u2713" : "<font color=#FFB4AB>" + version + " \u2717 needs 3.2.5</font>";
        } catch (PackageManager.NameNotFoundException e) {
            return "Not installed";
        }
    }

    private String appVersion() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "?";
        }
    }

    private void checkForAppUpdate() {
        try {
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                    new java.net.URL(
                            "https://api.github.com/repos/mitschud/samsu/releases/latest")
                            .openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setRequestProperty("User-Agent", "SamSU");
            if (conn.getResponseCode() != 200) return;
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream()));
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) body.append(line);
            reader.close();
            String tag = new org.json.JSONObject(body.toString()).optString("tag_name", "");
            if (tag.isEmpty()) return;
            if (tag.replaceFirst("^[vV]", "").trim()
                    .equalsIgnoreCase(appVersion())) return;
            ui.post(() -> updateChip.setVisibility(View.VISIBLE));
        } catch (Exception ignored) {
            /* Offline, rate-limited, or API hiccup: stay silent, keep the plain chip. */
        }
    }

    private static String normalizeKsuVersion(String versionName) {
        if (versionName == null) return "unknown";
        return versionName.replaceFirst("^[vV]", "").trim();
    }

    private void renderDashboard(M3qRootEngine.RootState state) {
        boolean shizukuRunning = ShizukuShell.isRunning();
        boolean shizukuGranted = ShizukuShell.isGranted();
        int shizukuUid = ShizukuShell.uid();
        String shizuku = !shizukuRunning ? "<font color=#FFB4AB>Not connected</font>"
                : !shizukuGranted ? "Permission required"
                : (shizukuUid == 2000 || shizukuUid == 0)
                ? "Connected" : "Permission limited";
        String attempted = engine.hasAttemptedThisBoot()
                ? (state.ready() ? "Rooted" : "Spent")
                : "Clean";
                dashboard.setText(Html.fromHtml(getString(R.string.dashboard_format,
                ksuManagerLabel(), shizuku, attempted), Html.FROM_HTML_MODE_LEGACY));
        boolean tileOk = state.ready();
        statusTile.setBackgroundResource(tileOk ? R.drawable.tile_ok : R.drawable.tile_bad);
        statusIcon.setImageResource(tileOk ? R.drawable.ic_sign_check : R.drawable.ic_sign_bad);
        payloadButton.setText(buildPayloadButtonLabel());
    }

    private void finishRun(M3qRootEngine.RootState state) {
        if (state.terminationUnconfirmed()) {
            finishUnconfirmedRun();
            return;
        }
        running.set(false);
        ui.post(() -> {
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            statusRefresh.setEnabled(true);
            if (state.ready()) {
                setStatus("Rooted", STATUS_SUCCESS);
                setStatusDetail("ADBsu root bridge loaded");
                run.setVisibility(View.GONE);
                openPackage(KSU_MANAGER_PACKAGE,
                        "Grant SU to SamSU and refresh.");
            } else if (state.bootstrap()) {
                run.setVisibility(View.VISIBLE);
                setStatus("Root ready", STATUS_WORKING);
                setStatusDetail("You can retry KernelSU activation.");
                run.setText(R.string.run_kernel_su_reactivate);
                run.setEnabled(true);
            } else {
                run.setVisibility(View.VISIBLE);
                setStatus("Failed", STATUS_WARNING);
                setStatusDetail("Kernel panic prevented, reboot required");
                run.setText(R.string.run_reboot_retry);
                runIsReboot = true;
                run.setEnabled(true);
            }
            reapplyModules.setEnabled(state.ready());
            restartZygote.setEnabled(state.ready());
            renderDashboard(state);
        });
    }

    private void finishUnconfirmedRun() {
        running.set(false);
        append("Process control was lost and exit could not be proven. Do not retry before rebooting.");
        ui.post(() -> {
            run.setVisibility(View.VISIBLE);
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            setStatus("Job status unknown", STATUS_WARNING);
            setStatusDetail("Do not run the same job again before rebooting.");
            run.setText(R.string.run_reboot_check);
            run.setEnabled(false);
            reapplyModules.setEnabled(false);
            restartZygote.setEnabled(false);
            unrootReboot.setEnabled(false);
            statusRefresh.setEnabled(true);
        });
    }

    private void openPackage(String packageName, String missingMessage) {
        Intent launch = getPackageManager().getLaunchIntentForPackage(packageName);
        if (launch == null) {
            append(missingMessage);
            setStatus("Grant in KernelSU", STATUS_NEUTRAL);
            setStatusDetail(missingMessage);
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(launch);
    }

    private void exportLastLog() {
        File file = engine.lastRootLog();
        if (!file.isFile()) {
            append("No run log to share yet.");
            setStatus("No diagnostic report", STATUS_NEUTRAL);
            setStatusDetail("Run Hold to root once to generate a report.");
            return;
        }
        try {
            String text = readLogTail(file);
            String stamp = new java.text.SimpleDateFormat("yyMMdd_HHmmss", Locale.US)
                    .format(new java.util.Date());
            String name = "SamSU diagnostics report_" + stamp + ".txt";
            android.content.ContentValues values = new android.content.ContentValues();
            values.put(android.provider.MediaStore.Downloads.DISPLAY_NAME, name);
            values.put(android.provider.MediaStore.Downloads.MIME_TYPE, "text/plain");
            android.net.Uri saved = getContentResolver().insert(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (saved == null) {
                throw new IOException("MediaStore insert failed");
            }
            try (java.io.OutputStream out = getContentResolver().openOutputStream(saved)) {
                if (out == null) {
                    throw new IOException("output stream unavailable");
                }
                out.write(text.getBytes(StandardCharsets.UTF_8));
            }
            append("Diagnostics exported: Downloads/" + name);
        } catch (IOException error) {
            append("Failed to export log: " + error.getMessage());
        }
    }

    private String readLogTail(File file) throws IOException {
        final int limit = 64 * 1024;
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            long skipped = Math.max(0, input.length() - limit);
            input.seek(skipped);
            byte[] bytes = new byte[(int) Math.min(limit, input.length())];
            input.readFully(bytes);
            String text = new String(bytes, StandardCharsets.UTF_8);
            if (skipped == 0) return text;
            return "[Head and truncated first lines omitted]\n"
                    + LogRedactor.dropPartialFirstLine(text);
        }
    }

    private void setStatus(String text, int semanticColor) {
        ui.post(() -> {
            int color = resolveStatusColor(semanticColor);
            status.setText(text);
            status.setTextColor(color);
            statusCard.setStrokeColor(color);
        });
    }

    private int resolveStatusColor(int semanticColor) {
        if (semanticColor == STATUS_SUCCESS) return getColor(R.color.m3q_success);
        if (semanticColor == STATUS_WORKING) return getColor(R.color.m3q_warning);
        if (semanticColor == STATUS_WARNING) return getColor(R.color.m3q_error);
        return getColor(R.color.m3q_neutral);
    }

    private void setStatusDetail(String text) {
        ui.post(() -> statusDetail.setText(text));
    }

    private void append(String line) {
        ui.post(() -> {
            log.append(line + "\n");
            if (diagnosticsVisible) {
                scrollLogToBottom();
            }
        });
    }

    private void scrollLogToBottom() {
        log.post(() -> {
            if (log.getLayout() == null) return;
            int scroll = log.getLayout().getLineTop(log.getLineCount())
                    - log.getHeight();
            log.scrollTo(0, Math.max(0, scroll));
        });
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(shizukuPermissionListener);
        worker.shutdown();
        super.onDestroy();
    }
}
