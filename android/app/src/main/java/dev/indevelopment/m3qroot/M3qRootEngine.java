package dev.indevelopment.m3qroot;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.SystemClock;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Context-only root workflow shared by the activity and foreground service. */
final class M3qRootEngine {
    interface Listener {
        void onStatus(String text, int color);

        void onLog(String line);
    }

    record RootState(boolean kernelSu, boolean bootstrap,
                     boolean terminationUnconfirmed, String output) {
        boolean ready() {
            return kernelSu;
        }
    }

    private static final String MODEL = "SM-S931B";
    private static final String KERNEL =
            "6.6.127-android15-8-p33f4ffe-abogkiS931BXXUCZZI4-4k";
    private static final String FINGERPRINT =
            "S931BXXUCZZI4";
    private static final long KIMAGE_BASE = 0xffffffc080000000L;
    private static final String HELPER = "libm3qroot.so";
    private static final String ORACLE = "libm3qoracle.so";
    private static final String PAYLOAD = "libm3qpayload.so";
    private static final String PAYLOAD_S938B = "libm3qpayload_s938b.so";
    private static final String KSUD = "libm3qksud.so";
    private static final String KSU_LOADER_PATH =
            "/data/local/tmp/ksud-s25u-kdp";
    private static final String KSU_STAGE_PATH = "/data/local/tmp/.ksud-stage";
    private static final String KSU_LOG_PATH =
            "/data/local/tmp/pa1q-kernelsu-late-load.log";
    private static final String KSU_MANAGER_PACKAGE = "me.weishu.kernelsu";
    private static final String STAGED_PAYLOAD = "/data/local/tmp/samsu-payload.so";
    private static final String MODULE_RELOAD_HOOK_DIR = "/data/adb/boot-completed.d";
    private static final String KSUD_SHA256 =
            "1e1cb6b861d0d4951b7374c12404eee1fb4c02a77240e0500ca571a302396374";
    private static final String SAFETY_PREFS = "kernel_run_safety";
    private static final String ATTEMPT_BOOT_ID = "attempt_boot_id";
    private static final String VERIFIED_KSU_BOOT_ID = "verified_ksu_boot_id";
    private static final String BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id";
    private static final int STATUS_WORKING = 0xff9a6700;
    static final int EXIT_TERMINATION_UNCONFIRMED = -1001;
    private static final long TERMINATION_WAIT_SECONDS = 3;
    private static final long READER_JOIN_SECONDS = 2;
    private static final Object ATTEMPT_LOCK = new Object();

    private static final Pattern ORACLE_KASLR = Pattern.compile(
            "slide-kaslr-ok source=physical .*?base=([0-9a-fA-F]+) " +
                    "slide=([0-9a-fA-F]+)");
    private static final Pattern ORACLE_DONE = Pattern.compile(
            "slide-only done base=([0-9a-fA-F]+) slide=([0-9a-fA-F]+) " +
                    "p0_offset=([0-9a-fA-F]+)");
    private static final Pattern ORACLE_KEEPER = Pattern.compile(
            "p0 reference keeper pid=([0-9]+) pipe=([0-9]+)");

    private final Context context;
    private final Listener listener;

    M3qRootEngine(Context context, Listener listener) {
        Objects.requireNonNull(context, "context");
        Context application = context.getApplicationContext();
        this.context = application != null ? application : context;
        this.listener = Objects.requireNonNull(listener, "listener");
    }

    boolean isSupported() {
        String kernel = System.getProperty("os.version", "");
        if (MODEL.equals(Build.MODEL)
                && KERNEL.equals(kernel)
                && Build.FINGERPRINT.contains(FINGERPRINT)) {
            return true;
        }
        // Same p33f4ffe GKI build ships across the S25 family in beta 2.
        if ("SM-S938B".equals(Build.MODEL)
                && kernel.startsWith("6.6.127-android15-8-p33f4ffe")
                && Build.FINGERPRINT.contains("S938BXXUCZZI4")) {
            return true;
        }
        return "SM-S936B".equals(Build.MODEL)
                && kernel.startsWith("6.6.127-android15-8-p33f4ffe")
                && Build.FINGERPRINT.contains("S936BXXUCZZI4");
    }

    RootState checkRoot(boolean verbose) {
        File helper = nativeFile(HELPER);
        if (!helper.isFile()) {
            return new RootState(false, false, false, "helper missing");
        }

        List<String> ksuLines = new ArrayList<>();
        int ksuCode = 127;
        boolean authoritativeProbe = false;
        if (ShizukuShell.isRunning() && ShizukuShell.isGranted()) {
            int uid = ShizukuShell.uid();
            if (uid == 2000 || uid == 0) {
                String[] command = {helper.getAbsolutePath(), "--ksu-info"};
                String[] environment = {
                        "HOME=/data/local/tmp",
                        "TMPDIR=/data/local/tmp",
                        "PATH=/system/bin:/system/xbin"
                };
                try {
                    Process process = ShizukuShell.exec(
                            command, environment, "/data/local/tmp");
                    authoritativeProbe = true;
                    ksuCode = runProcess(process, 8, ksuLines, verbose);
                } catch (RuntimeException e) {
                    if (verbose) log("Shizuku KernelSU check error: " + e.getMessage());
                    if (e instanceof ShizukuShell.ProcessControlLostException) {
                        return new RootState(false, false, true, e.getMessage());
                    }
                }
            }
        }
        if (Thread.currentThread().isInterrupted()) {
            return new RootState(false, false, false, "interrupted");
        }
        String ksuOutput = String.join("\n", ksuLines);
        if (ksuCode == EXIT_TERMINATION_UNCONFIRMED) {
            return new RootState(false, false, true, ksuOutput);
        }
        boolean kernelSu = ksuCode == 0
                && ksuOutput.contains("KernelSU control verified version=32525");
        if (kernelSu) {
            markKernelSuVerifiedForThisBoot();
            return new RootState(true, false, false, ksuOutput);
        }
        if (!authoritativeProbe && hasVerifiedKernelSuThisBoot()) {
            return new RootState(true, false, false,
                    "KernelSU control verified by the root daemon for this boot");
        }

        ProcessBuilder bootstrap = new ProcessBuilder(
                helper.getAbsolutePath(), "-c", "id");
        bootstrap.redirectErrorStream(true);
        List<String> bootstrapLines = new ArrayList<>();
        int bootstrapCode = runProcess(bootstrap, 8, bootstrapLines, verbose);
        String bootstrapOutput = String.join("\n", bootstrapLines);
        if (bootstrapCode == EXIT_TERMINATION_UNCONFIRMED) {
            return new RootState(false, false, true,
                    ksuOutput + "\n" + bootstrapOutput);
        }
        return new RootState(false,
                bootstrapCode == 0 && bootstrapOutput.contains("uid=0(root)"),
                false,
                ksuOutput + "\n" + bootstrapOutput);
    }

    int runFreshRoot(boolean useShizuku) {
        File helper = nativeFile(HELPER);
        File payload = activePayload();
        File ksud = activeKsud();
        if (!helper.isFile() || !payload.isFile() || !ksud.isFile()) {
            log("Required native files not found in APK.");
            return 126;
        }

        if (useShizuku) {
            payload = stagePayloadForShell(payload);
            stageKsudForShell(ksud);
            int rootCode = runShizukuTracefsRoot(helper, payload);
            return rootCode == 0 ? activateKernelSu(helper, ksud, true) : rootCode;
        }

        status("Checking device security state", STATUS_WORKING);
        log("1/1: running root-single through the kernel gate");
        ProcessBuilder rootProcess = payloadProcess(helper, payload);
        Map<String, String> env = rootProcess.environment();
        configureRootEnvironment(env, false, null);
        List<String> rootLines = new ArrayList<>();
        int rootCode = runProcess(rootProcess, 600, rootLines, true);
        if (rootCode != EXIT_TERMINATION_UNCONFIRMED) {
            saveRootLog(rootLines, rootCode);
        } else {
            log("Process exit not confirmed; skipping root log finalization.");
        }
        return rootCode == 0 ? activateKernelSu(helper, ksud, true) : rootCode;
    }

    int activateKernelSu() {
        return activateKernelSu(nativeFile(HELPER), activeKsud(), true);
    }

    int reapplyKernelSuModules() {
        File ksud = activeKsud();
        if (!ksud.isFile()) {
            log("KernelSU binary not found in APK.");
            return 126;
        }

        String token = Long.toHexString(SystemClock.elapsedRealtimeNanos());
        String marker = "/data/local/tmp/.m3q-module-reload-" + token;
        String hook = MODULE_RELOAD_HOOK_DIR
                + "/99-m3q-module-reload-" + token + ".sh";
        String command = kernelSuRootPreamble(ksud)
                + "stage=" + shellQuote(KSU_STAGE_PATH) + "\n"
                + "hook=" + shellQuote(hook) + "\n"
                + "marker=" + shellQuote(marker) + "\n"
                + "cleanup() { rm -f -- \"$stage\" \"$hook\" \"$marker\"; }\n"
                + "trap cleanup EXIT HUP INT TERM\n"
                + "rm -f -- \"$stage\"\n"
                + "cp \"$ksud\" \"$stage\"\n"
                + "chmod 0755 \"$stage\"\n"
                + "stage_hash=$(sha256sum \"$stage\"); stage_hash=${stage_hash%% *}\n"
                + "if [ \"$stage_hash\" != \"$hash\" ]; then\n"
                + "  echo M3Q_KSUD_STAGE_HASH_MISMATCH:$stage_hash\n"
                + "  exit 125\n"
                + "fi\n"
                + "mkdir -p " + shellQuote(MODULE_RELOAD_HOOK_DIR) + "\n"
                + "rm -f -- \"$hook\" \"$marker\"\n"
                + "cat > \"$hook\" <<'M3Q_MODULE_RELOAD_HOOK'\n"
                + "#!/system/bin/sh\n"
                + "printf '%s\\n' " + shellQuote(token) + " > "
                + shellQuote(marker) + "\n"
                + "rm -f -- \"$0\"\n"
                + "exit 0\n"
                + "M3Q_MODULE_RELOAD_HOOK\n"
                + "chmod 0755 \"$hook\"\n"
                + "\"$ksud\" late-load --kmi " + activeKmi() + " --allow-shell --package-name "
                + KSU_MANAGER_PACKAGE + "\n"
                + "i=0\n"
                + "while [ \"$i\" -lt 120 ]; do\n"
                + "  if [ -f \"$marker\" ]; then\n"
                + "    echo M3Q_MODULE_RELOAD_OK:" + token + "\n"
                + "    exit 0\n"
                + "  fi\n"
                + "  i=$((i + 1))\n"
                + "  sleep 1\n"
                + "done\n"
                + "echo M3Q_MODULE_RELOAD_TIMEOUT\n"
                + "exit 124\n";

        status("Reloading KernelSU module", STATUS_WORKING);
        List<String> output = new ArrayList<>();
        int code = runKernelSuRootCommand(ksud, command, 150, output);
        if (code != 0) {
            log("KernelSU module reapply failed code=" + code);
            return code;
        }
        if (!String.join("\n", output).contains("M3Q_MODULE_RELOAD_OK:" + token)) {
            log("KernelSU boot-completed completion marker not confirmed.");
            return 125;
        }
        log("KernelSU module late-load reapplied");
        return 0;
    }

    int restartZygote() {
        File ksud = activeKsud();
        if (!ksud.isFile()) {
            log("KernelSU binary not found in APK.");
            return 126;
        }
        String command = kernelSuRootPreamble(ksud)
                + "echo M3Q_ZYGOTE_RESTART_REQUESTED\n"
                + "if [ \"$(getprop init.svc.zygote_secondary)\" = running ]; then\n"
                + "  setprop ctl.restart zygote_secondary\n"
                + "fi\n"
                + "setprop ctl.restart zygote\n";
        return runKernelSuRootCommand(ksud, command, 15, new ArrayList<>());
    }

    String currentBootId() {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                new FileInputStream(BOOT_ID_PATH), StandardCharsets.US_ASCII))) {
            String bootId = in.readLine();
            return bootId == null ? "" : bootId.trim();
        } catch (IOException e) {
            return "";
        }
    }

    static long bootSettleRemainingMillis() {
        return RootSafetyPolicy.bootSettleRemainingMillis(SystemClock.elapsedRealtime());
    }

    boolean markAttemptForThisBoot() {
        if (bootSettleRemainingMillis() > 0) return false;
        synchronized (ATTEMPT_LOCK) {
            String bootId = currentBootId();
            if (bootId.isEmpty()) return false;
            SharedPreferences prefs = preferences();
            if (bootId.equals(prefs.getString(ATTEMPT_BOOT_ID, ""))) return false;
            return prefs.edit().putString(ATTEMPT_BOOT_ID, bootId).commit();
        }
    }

    boolean hasAttemptedThisBoot() {
        String bootId = currentBootId();
        if (bootId.isEmpty()) return true;
        String attempted = preferences().getString(ATTEMPT_BOOT_ID, "");
        return bootId.equals(attempted);
    }

    boolean hasVerifiedKernelSuThisBoot() {
        String bootId = currentBootId();
        if (bootId.isEmpty()) return false;
        String verified = preferences().getString(VERIFIED_KSU_BOOT_ID, "");
        return bootId.equals(verified);
    }

    File lastRootLog() {
        File directory = context.getExternalFilesDir(null);
        if (directory == null) directory = context.getFilesDir();
        return new File(directory, "last-root.log");
    }

    private int runShizukuTracefsRoot(File helper, File payload) {
        int uid = ShizukuShell.uid();
        if (uid != 2000 && uid != 0) {
            log("Shizuku is not running as shell/root UID; refusing to run.");
            return 126;
        }
        status("Activating via Shizuku", STATUS_WORKING);
        log("1/1: running root-single via the shell tracefs KASLR gate");
        Map<String, String> env = new HashMap<>();
        env.put("HOME", "/data/local/tmp");
        env.put("TMPDIR", "/data/local/tmp");
        env.put("PATH", "/system/bin:/system/xbin");
        configureRootEnvironment(env, true, null);
        String[] environment = new String[env.size()];
        int index = 0;
        for (Map.Entry<String, String> entry : env.entrySet()) {
            environment[index++] = entry.getKey() + "=" + entry.getValue();
        }
        String[] command = {
                helper.getAbsolutePath(), "--run-payload",
                payload.getAbsolutePath(), helper.getAbsolutePath(),
                "/data/local/tmp/payload_run.log"
        };
        try {
            Process process = ShizukuShell.exec(command, environment, "/data/local/tmp");
            List<String> rootLines = new ArrayList<>();
            int rootCode = runProcess(process, 600, rootLines, true);
            if (rootCode != EXIT_TERMINATION_UNCONFIRMED) {
                saveRootLog(rootLines, rootCode);
            } else {
                log("Process exit not confirmed; skipping root log finalization.");
            }
            return rootCode;
        } catch (RuntimeException e) {
            log("Shizuku run error: " + e.getMessage());
            return e instanceof ShizukuShell.ProcessControlLostException
                    ? EXIT_TERMINATION_UNCONFIRMED : 127;
        }
    }

    private void configureRootEnvironment(Map<String, String> env,
                                          boolean tracefs, String slide) {
        // "auto" is the only safe universal value: tracefs-capable payloads
        // (bundled pa1q) still prefer the tracefs route first, while registry
        // payloads built without APP_TRACEFS_SLIDE reject "tracefs" outright
        // ("slide unknown source") and fail before the physical route runs.
        env.put("SLIDE_SOURCE", "auto");
        env.put("CVE43499_ROOT_HELPER",
                nativeFile(HELPER).getAbsolutePath());
        env.put("EXPLOIT_ATTEMPT_TIMEOUT_SEC", "600");
        env.put("P0_ATTEMPT_TIMEOUT_SEC", "90");
    }

    private int activateKernelSu(File helper, File ksud, boolean allowGrantWait) {
        if (!helper.isFile() || !ksud.isFile()) {
            log("KernelSU loader not found in APK.");
            return 126;
        }

        status("Verifying KernelSU", STATUS_WORKING);
        String source = shellQuote(ksud.getAbsolutePath());
        String loader = shellQuote(KSU_LOADER_PATH);
        String stage = shellQuote(KSU_STAGE_PATH);
        boolean bundledKsud = ksudIsBundled();
        String sizeGuard = bundledKsud ? "" :
                "test \"$(stat -c %s " + source + ")\" = "
                        + ksudOverrideSize + "; ";
        String hashTests = bundledKsud
                ? "test \"$h1\" = " + KSUD_SHA256 + "; " +
                  "test \"$h2\" = " + KSUD_SHA256 + "; "
                : "";
        String command = "set -eu; umask 022; mkdir -p /data/adb; " +
                sizeGuard +
                "cp " + source + " " + loader + "; " +
                "cp " + source + " " + stage + "; " +
                "chmod 0755 " + loader + " " + stage + "; " +
                "h1=$(sha256sum " + loader + "); h1=${h1%% *}; " +
                "h2=$(sha256sum " + stage + "); h2=${h2%% *}; " +
                hashTests +
                "echo KSU_STAGE_OK:$h1";

        List<String> stageLines = new ArrayList<>();
        ProcessBuilder stageProcess = new ProcessBuilder(
                helper.getAbsolutePath(), "-c", command);
        stageProcess.redirectErrorStream(true);
        int stageCode = runProcess(stageProcess, 30, stageLines, true);
        appendRootLogSection("KernelSU staging", stageLines, stageCode);
        if (Thread.currentThread().isInterrupted()) return stageCode;
        if (stageCode == EXIT_TERMINATION_UNCONFIRMED
                || stageCode == 124 || stageCode == 130) {
            return EXIT_TERMINATION_UNCONFIRMED;
        }
        String stageOutput = String.join("\n", stageLines);
        String expectedMarker = "KSU_STAGE_OK:" + KSUD_SHA256;
        if (stageCode != 0 || !stageOutput.contains(expectedMarker)) {
            if (allowGrantWait
                    && stageOutput.toLowerCase().contains("permission denied")) {
                return waitAndRetryAfterGrant(helper, ksud);
            }
            log("KernelSU staging verification failed");
            return 125;
        }

        log("KernelSU loader SHA-256 match");
        status("Activating KernelSU", STATUS_WORKING);
        ProcessBuilder loadProcess = new ProcessBuilder(
                helper.getAbsolutePath(), "--late-load");
        loadProcess.redirectErrorStream(true);
        java.util.List<String> loadLines = new ArrayList<>();
        int loadCode = runProcess(loadProcess, 180, loadLines, true);
        appendRootLogSection("KernelSU late-load", loadLines, loadCode);
        if (Thread.currentThread().isInterrupted()) return loadCode;
        if (loadCode == EXIT_TERMINATION_UNCONFIRMED
                || loadCode == 124 || loadCode == 130) {
            return EXIT_TERMINATION_UNCONFIRMED;
        }
        if (loadCode != 0) {
            log("KernelSU late-load failed code=" + loadCode);
            appendKernelSuLog(helper);
            return loadCode;
        }

        /* The daemon verifies KernelSU in a seccomp-free context. A direct
         * untrusted_app discovery syscall is killed by Samsung seccomp. */
        if (!markKernelSuVerifiedForThisBoot()) {
            log("KernelSU loaded, but failed to store the verification receipt for this boot ID.");
            return 123;
        }

        RootState state = checkRoot(true);
        if (state.terminationUnconfirmed()) {
            return EXIT_TERMINATION_UNCONFIRMED;
        }
        if (!state.ready()) {
            log("Late-load finished, but KernelSU control verification failed.");
            return 124;
        }
        log("KernelSU 3.2.5 LKM late-load verified");
        return 0;
    }

    /**
    /**
    /**
     * Fresh setups can have KernelSU reject the app's first su request after
     * the driver late-loads, and that denial can persist even once the
     * driver is up. The payload's root daemon late-loads the persisted
     * ksud on its own schedule, so instead of retrying su we verify
     * KernelSU control directly and give it up to 12 seconds to come up.
     */
    private int waitAndRetryAfterGrant(File helper, File ksud) {
        final int waitTotalSeconds = 12;
        final int probeIntervalSeconds = 2;
        status("Verifying KernelSU", STATUS_WORKING);
        log("KernelSU rejected the app's su request; the payload daemon "
                + "brings the driver up on its own. Verifying KernelSU "
                + "control directly every " + probeIntervalSeconds
                + " seconds (up to " + waitTotalSeconds + " seconds).");
        for (int elapsed = 0; elapsed <= waitTotalSeconds;
                elapsed += probeIntervalSeconds) {
            if (elapsed > 0) {
                try {
                    Thread.sleep(probeIntervalSeconds * 1000L);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    return 125;
                }
            }
            RootState state = checkRoot(false);
            if (state.terminationUnconfirmed()) {
                return EXIT_TERMINATION_UNCONFIRMED;
            }
            if (state.ready()) {
                log("KernelSU active after " + elapsed + " seconds; "
                        + "su-based staging not required.");
                status("KernelSU active", 0xff94cf86);
                return 0;
            }
            if (elapsed < waitTotalSeconds) {
                log("KernelSU control not ready yet after " + elapsed
                        + " seconds; still verifying ...");
            }
        }
        status("KernelSU root denied - reboot and run again", 0xffffb4ab);
        log("KernelSU did not become active within " + waitTotalSeconds
                + " seconds. Reboot and run again.");
        return 125;
    }

    private void appendKernelSuLog(File helper) {
        ProcessBuilder logProcess = new ProcessBuilder(
                helper.getAbsolutePath(), "-c",
                "test ! -r " + shellQuote(KSU_LOG_PATH) + " || cat " +
                        shellQuote(KSU_LOG_PATH));
        logProcess.redirectErrorStream(true);
        runProcess(logProcess, 10);
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private String kernelSuRootPreamble(File ksud) {
        return "set -eu\n"
                + "ksud=" + shellQuote(ksud.getAbsolutePath()) + "\n"
                + "if [ \"$(id -u)\" != 0 ]; then\n"
                + "  echo M3Q_ROOT_PERMISSION_REQUIRED\n"
                + "  exit 126\n"
                + "fi\n"
                + (ksudIsBundled()
                        ? "hash=$(sha256sum \"$ksud\"); hash=${hash%% *}\n"
                          + "if [ \"$hash\" != " + KSUD_SHA256 + " ]; then\n"
                          + "  echo M3Q_KSUD_HASH_MISMATCH:$hash\n"
                          + "  exit 125\n"
                          + "fi\n"
                        : "")
                + "info=$(\"$ksud\" debug info 2>&1)\n"
                + "printf '%s\\n' \"$info\"\n"
                + "printf '%s\\n' \"$info\" | grep -Fqx 'version: 32525' || exit 125\n"
                + "printf '%s\\n' \"$info\" | grep -Fqx 'late_load: true' || exit 125\n";
    }

    private int runKernelSuRootCommand(File ksud, String command, int timeoutSeconds,
                                       List<String> output) {
        ProcessBuilder processBuilder = new ProcessBuilder(
                ksud.getAbsolutePath(), "debug", "su", "-g");
        processBuilder.directory(context.getFilesDir());
        processBuilder.redirectErrorStream(true);
        processBuilder.environment().put("HOME", "/data/local/tmp");
        processBuilder.environment().put("TMPDIR", "/data/local/tmp");
        processBuilder.environment().put("PATH", "/system/bin:/system/xbin");
        try {
            Process process = processBuilder.start();
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    process.getOutputStream(), StandardCharsets.UTF_8))) {
                writer.write(command);
                writer.newLine();
                writer.write("exit");
                writer.newLine();
            }
            return runProcess(process, timeoutSeconds, output, true);
        } catch (IOException e) {
            log("KernelSU root shell error: " + e.getMessage());
            return 127;
        }
    }

    int rebootDevice() {
        List<String> output = new ArrayList<>();
        int code = runKernelSuRootCommand(activeKsud(), "reboot", 30, output);
        for (String line : output) log(line);
        return code;
    }

    private ProcessBuilder payloadProcess(File helper, File payload) {
        ProcessBuilder process = new ProcessBuilder(
                helper.getAbsolutePath(), "--run-payload",
                payload.getAbsolutePath(), helper.getAbsolutePath(),
                "/data/local/tmp/payload_run.log");
        process.directory(context.getFilesDir());
        process.redirectErrorStream(true);
        process.environment().put("HOME", context.getFilesDir().getAbsolutePath());
        process.environment().put("TMPDIR", context.getCacheDir().getAbsolutePath());
        return process;
    }

    private SlideVerdict parseOracleVerdict(List<String> lines) {
        Long kaslrBase = null;
        Long kaslrSlide = null;
        Long doneBase = null;
        Long doneSlide = null;
        Long p0Offset = null;
        int keeperPid = -1;
        try {
            for (String line : lines) {
                Matcher kaslr = ORACLE_KASLR.matcher(line);
                if (kaslr.find()) {
                    if (kaslrBase != null) return null;
                    kaslrBase = Long.parseUnsignedLong(kaslr.group(1), 16);
                    kaslrSlide = Long.parseUnsignedLong(kaslr.group(2), 16);
                }
                Matcher done = ORACLE_DONE.matcher(line);
                if (done.find()) {
                    if (doneBase != null) return null;
                    doneBase = Long.parseUnsignedLong(done.group(1), 16);
                    doneSlide = Long.parseUnsignedLong(done.group(2), 16);
                    p0Offset = Long.parseUnsignedLong(done.group(3), 16);
                }
                Matcher keeper = ORACLE_KEEPER.matcher(line);
                if (keeper.find()) {
                    keeperPid = Integer.parseInt(keeper.group(1));
                }
            }
        } catch (NumberFormatException ignored) {
            return null;
        }
        if (kaslrBase == null || kaslrSlide == null || doneBase == null
                || doneSlide == null || p0Offset == null
                || !kaslrBase.equals(doneBase) || !kaslrSlide.equals(doneSlide)
                || !kaslrSlide.equals(p0Offset) || kaslrSlide > 0x1f0000L
                || (kaslrSlide & 0xffffL) != 0
                || kaslrBase != KIMAGE_BASE + kaslrSlide) {
            return null;
        }
        return new SlideVerdict(kaslrSlide,
                String.format(Locale.ROOT, "0x%x", kaslrSlide), keeperPid);
    }

    private boolean markKernelSuVerifiedForThisBoot() {
        String bootId = currentBootId();
        if (bootId.isEmpty()) return false;
        return preferences().edit()
                .putString(VERIFIED_KSU_BOOT_ID, bootId).commit();
    }

    private SharedPreferences preferences() {
        return context.getSharedPreferences(SAFETY_PREFS, Context.MODE_PRIVATE);
    }

    private int runProcess(ProcessBuilder process, int timeoutSeconds) {
        return runProcess(process, timeoutSeconds, null, true);
    }

    private int runProcess(ProcessBuilder process, int timeoutSeconds,
                           List<String> capture, boolean display) {
        try {
            return runProcess(process.start(), timeoutSeconds, capture, display);
        } catch (IOException e) {
            if (display) log("Run error: " + e.getMessage());
            return 127;
        }
    }

    private int runProcess(Process process, int timeoutSeconds,
                           List<String> capture, boolean display) {
        InputStream processStdout = process.getInputStream();
        InputStream processStderr = process.getErrorStream();
        Thread stdout = streamReader(processStdout, capture, display,
                "m3q-root-stdout");
        Thread stderr = streamReader(processStderr, capture, display,
                "m3q-root-stderr");
        stdout.start();
        stderr.start();
        boolean[] interrupted = {false};
        boolean processEnded = false;
        int result = 127;
        try {
            processEnded = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (processEnded) {
                result = process.exitValue();
            } else {
                processEnded = terminateAndWait(process, interrupted);
                result = processEnded ? 124 : EXIT_TERMINATION_UNCONFIRMED;
            }
        } catch (InterruptedException e) {
            interrupted[0] = true;
            processEnded = terminateAndWait(process, interrupted);
            result = processEnded ? 130 : EXIT_TERMINATION_UNCONFIRMED;
        } catch (RuntimeException e) {
            processEnded = terminateAndWait(process, interrupted);
            if (display) log("Run error: " + e.getMessage());
            result = processEnded ? 127 : EXIT_TERMINATION_UNCONFIRMED;
        } finally {
            closeQuietly(process.getOutputStream());
            if (!processEnded) {
                closeQuietly(processStdout);
                closeQuietly(processStderr);
            }
            boolean stdoutDone = joinReader(stdout, READER_JOIN_SECONDS, interrupted);
            boolean stderrDone = joinReader(stderr, READER_JOIN_SECONDS, interrupted);
            if (!stdoutDone || !stderrDone) {
                closeQuietly(processStdout);
                closeQuietly(processStderr);
                stdoutDone = joinReader(stdout, 1, interrupted);
                stderrDone = joinReader(stderr, 1, interrupted);
            }
            closeQuietly(processStdout);
            closeQuietly(processStderr);
            if (display && (!stdoutDone || !stderrDone)) {
                log("Could not confirm process output stream exit.");
            }
            if (interrupted[0]) Thread.currentThread().interrupt();
        }
        if (result == EXIT_TERMINATION_UNCONFIRMED && display) {
            log("Could not confirm process group exit. Do not retry this boot.");
        }
        return result;
    }

    private static boolean terminateAndWait(Process process, boolean[] interrupted) {
        try {
            process.destroy();
        } catch (RuntimeException ignored) {
        }
        if (awaitProcessExit(process, TERMINATION_WAIT_SECONDS, interrupted)) {
            return true;
        }
        try {
            process.destroyForcibly();
        } catch (RuntimeException ignored) {
        }
        return awaitProcessExit(process, TERMINATION_WAIT_SECONDS, interrupted);
    }

    private static boolean awaitProcessExit(Process process, long timeoutSeconds,
                                            boolean[] interrupted) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
        while (true) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) return false;
            try {
                if (process.waitFor(Math.min(remaining,
                        TimeUnit.MILLISECONDS.toNanos(250)), TimeUnit.NANOSECONDS)) {
                    return true;
                }
            } catch (InterruptedException ignored) {
                interrupted[0] = true;
            } catch (RuntimeException ignored) {
                return false;
            }
        }
    }

    private static boolean joinReader(Thread reader, long timeoutSeconds,
                                      boolean[] interrupted) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
        while (reader.isAlive()) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) break;
            try {
                reader.join(Math.max(1, Math.min(
                        TimeUnit.NANOSECONDS.toMillis(remaining), 250)));
            } catch (InterruptedException ignored) {
                interrupted[0] = true;
            }
        }
        if (reader.isAlive()) reader.interrupt();
        return !reader.isAlive();
    }

    private static void closeQuietly(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException ignored) {
        }
    }

    /** Payload output embeds ANSI color codes (ESC[32m ... ESC[0m); strip
     * them so the log panel and exported run log stay readable. */
    private static final Pattern ANSI_ESCAPE =
            Pattern.compile("\\u001B\\[[0-9;]*[A-Za-z]");

    private static String stripAnsi(String line) {
        return line == null ? "" : ANSI_ESCAPE.matcher(line).replaceAll("");
    }

    private Thread streamReader(InputStream stream, List<String> capture,
                                boolean display, String name) {
        Thread reader = new Thread(() -> {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(
                    stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = in.readLine()) != null) {
                    line = stripAnsi(line);
                    if (capture != null) {
                        synchronized (capture) {
                            capture.add(line);
                        }
                    }
                    if (display) log(line);
                }
            } catch (IOException ignored) {
            }
        }, name);
        reader.setDaemon(true);
        return reader;
    }

    /** Installed SamSU version name, e.g. "1.66". */
    private String appVersionName() {
        try {
            android.content.pm.PackageInfo info =
                    context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0);
            return info.versionName != null ? info.versionName : "?";
        } catch (Exception error) {
            return "?";
        }
    }

    /** Firmware build tag from the running kernel vermagic, e.g.
     *  "S936BXXUCZZI4" from 6.6.127-android15-8-p33f4ffe-abogkiS936BXXUCZZI4-4k. */
    private String firmwareTag() {
        String kernel = System.getProperty("os.version", "");
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("abogki([A-Za-z0-9]+)-[0-9]+k").matcher(kernel);
        return matcher.find() ? matcher.group(1) : "";
    }

    /** Short firmware name, e.g. "S936BZZI4" (model + final revision). */
    private String firmwareShortName() {
        String tag = firmwareTag();
        if (tag.isEmpty()) return "";
        int cut = tag.indexOf("XXU");
        return cut > 0 ? tag.substring(0, cut) + tag.substring(cut + 4) : tag;
    }

    private void saveRootLog(List<String> lines, int exitCode) {
        File output = lastRootLog();
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output, false), StandardCharsets.UTF_8))) {
            writer.write("samsu_version=" + appVersionName());
            writer.newLine();
            writer.write("firmware=" + firmwareTag()
                    + (firmwareShortName().isEmpty()
                        ? "" : " (" + firmwareShortName() + ")"));
            writer.newLine();
            writer.write("boot_id=" + currentBootId());
            writer.newLine();
            writer.write("exit=" + exitCode);
            writer.newLine();
            synchronized (lines) {
                for (String line : lines) {
                    writer.write(line);
                    writer.newLine();
                }
            }
            log("Saving run log: " + output.getAbsolutePath());
        } catch (IOException e) {
            log("Failed to save run log: " + e.getMessage());
        }
    }
    private void appendRootLogSection(String title, java.util.List<String> lines, int exitCode) {
        File output = lastRootLog();
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output, true), StandardCharsets.UTF_8))) {
            writer.write("==== " + title + " exit=" + exitCode + " ====");
            writer.newLine();
            synchronized (lines) {
                for (String line : lines) {
                    writer.write(line);
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            log("Failed to append run log: " + e.getMessage());
        }
    }

    private volatile File payloadOverride;

    /** Registry-provided ksud for the active payload; null = bundled build. */
    private volatile File ksudOverride;
    private volatile long ksudOverrideSize = -1;
    private volatile String kmiOverride;

    void setKsudOverride(File file, long expectedSize) {
        ksudOverride = file;
        ksudOverrideSize = expectedSize;
    }

    void setKmiOverride(String kmi) {
        kmiOverride = kmi;
    }

    private File activeKsud() {
        File override = ksudOverride;
        return (override != null && override.isFile())
                ? override : nativeFile(KSUD);
    }

    private boolean ksudIsBundled() {
        File override = ksudOverride;
        return override == null || !override.isFile();
    }

    private String activeKmi() {
        String kmi = kmiOverride;
        return (kmi == null || kmi.isEmpty()) ? "android15-6.6" : kmi;
    }

    void setPayloadOverride(File file) {
        payloadOverride = file;
    }

    /*
     * Downloaded payloads live in this app's private filesDir, which the
     * shell-uid helper (run through Shizuku) cannot reach. Stage the bytes
     * into /data/local/tmp via the Shizuku shell so the helper can dlopen
     * them, mirroring the documented RMG deployment layout.
     */
    private void stageKsudForShell(File ksud) {
        if (!ShizukuShell.isRunning() || !ShizukuShell.isGranted()) {
            log("Shizuku unavailable for KernelSU staging; the daemon "
                    + "will use its own schedule.");
            return;
        }
        try {
            Process process = ShizukuShell.exec(new String[]{
                    "sh", "-c", "cat > " + KSU_LOADER_PATH
                            + " && chmod 0755 " + KSU_LOADER_PATH},
                    new String[]{
                            "PATH=/system/bin:/system/xbin",
                            "HOME=/data/local/tmp",
                            "TMPDIR=/data/local/tmp"},
                    "/data/local/tmp");
            try (java.io.OutputStream out = process.getOutputStream()) {
                java.nio.file.Files.copy(ksud.toPath(), out);
            }
            int code = process.waitFor();
            if (code == 0) {
                log("KernelSU daemon staged to " + KSU_LOADER_PATH);
            } else {
                log("KernelSU daemon staging failed code=" + code);
            }
        } catch (Exception error) {
            log("KernelSU daemon staging error: " + error.getMessage());
        }
    }

    private File stagePayloadForShell(File payload) {
        if (payload.getAbsolutePath().equals(
                nativeFile(PAYLOAD).getAbsolutePath())) {
            return payload;
        }
        if (!ShizukuShell.isRunning() || !ShizukuShell.isGranted()) {
            log("Shizuku unavailable for payload staging; using the original path.");
            return payload;
        }
        try {
            Process process = ShizukuShell.exec(new String[]{
                    "sh", "-c", "cat > " + STAGED_PAYLOAD
                            + " && chmod 0644 " + STAGED_PAYLOAD},
                    new String[]{
                            "PATH=/system/bin:/system/xbin",
                            "HOME=/data/local/tmp",
                            "TMPDIR=/data/local/tmp"},
                    "/data/local/tmp");
            try (java.io.OutputStream out = process.getOutputStream()) {
                java.nio.file.Files.copy(payload.toPath(), out);
            }
            int code = process.waitFor();
            File staged = new File(STAGED_PAYLOAD);
            if (code == 0 && staged.isFile()
                    && staged.length() == payload.length()) {
                log("Staged payload " + STAGED_PAYLOAD
                        + " (" + staged.length() + " bytes).");
                return staged;
            }
            log("Payload staging failed code=" + code
                    + "; using the original path.");
        } catch (Exception error) {
            log("Payload staging failed: " + error.getMessage());
        }
        return payload;
    }
    private File activePayload() {
        File override = payloadOverride;
        if (override != null && override.isFile()) return override;
        return nativeFile(bundledPayloadLib);
    }

    /** Which bundled payload library to fall back to (S931B default). */
    private volatile String bundledPayloadLib = PAYLOAD;

    void setBundledPayloadLib(String libName) {
        bundledPayloadLib = libName == null || libName.isEmpty()
                ? PAYLOAD : libName;
    }

    private File nativeFile(String name) {
        return new File(context.getApplicationInfo().nativeLibraryDir, name);
    }

    private void status(String text, int color) {
        listener.onStatus(text, color);
    }

    private void log(String line) {
        listener.onLog(line);
    }

    private record SlideVerdict(long slide, String argument, int keeperPid) {
    }
}
