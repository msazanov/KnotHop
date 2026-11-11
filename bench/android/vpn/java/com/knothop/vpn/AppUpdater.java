package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.provider.Settings;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Обновление приложения из самого приложения. Порядок: тег релиза (его даёт {@link UpdateCheck}) -> SHA256SUMS ровно этого тега ->
 * knothop.apk этого же тега в cacheDir/updates -> проверки (sha256 == строка knothop.apk, тот же пакет, та же подпись, versionCode больше)
 * -> подтверждение пользователя -> PackageInstaller (система ещё раз показывает своё подтверждение).
 * Только HTTPS, редиректы идут вручную и только на хосты GitHub; размер ограничен; секретов и путей в журнал не пишем.
 * Установка перезапускает процесс и рвёт туннель - об этом предупреждает диалог.
 */
final class AppUpdater {
    static final String ACTION_RESULT = "com.knothop.vpn.UPDATE_INSTALL_RESULT";
    private static final String BASE = "https://github.com/msazanov/KnotHop/releases/download/";
    private static final long MAX_APK = 64L << 20;
    private static final int MAX_SUMS = 64 * 1024;
    private static final Pattern TAG = Pattern.compile("v\\d{1,4}\\.\\d{1,4}\\.\\d{1,9}");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final long STALE_MS = 2L * 3600 * 1000;

    private static volatile boolean running;

    private final Activity act;
    private final SharedPreferences sp;
    private final Handler ui;
    private volatile boolean cancel;
    private AlertDialog progress;
    private ProgressBar bar;
    private TextView label;

    /** Проверка не прошла: текст готов для показа пользователю. */
    private static final class Refusal extends Exception {
        Refusal(String m) { super(m); }
    }

    AppUpdater(Activity act, SharedPreferences sp, Handler ui) {
        this.act = act;
        this.sp = sp;
        this.ui = ui;
    }

    // ---- файлы

    static File dir(Context c) {
        File d = new File(c.getCacheDir(), "updates");
        if (!d.isDirectory()) d.mkdirs();
        return d;
    }

    /** Старые и недокачанные файлы (после сбоя, убитого процесса): `.part` и всё старше двух часов. */
    static void cleanup(Context c) {
        File[] fs = dir(c).listFiles();
        if (fs == null) return;
        long now = System.currentTimeMillis();
        for (File f : fs) {
            if (f.getName().endsWith(".part") || now - f.lastModified() > STALE_MS) f.delete();
        }
    }

    private static void wipe(Context c) {
        File[] fs = dir(c).listFiles();
        if (fs != null) for (File f : fs) f.delete();
    }

    private void forget() {
        sp.edit().remove("upd_file").remove("upd_sha").remove("upd_tag").remove("upd_wait_perm").apply();
        wipe(act);
    }

    // ---- запуск скачивания (пользователь уже согласился)

    void start(final String tag) {
        if (running) { Toast.makeText(act, "Обновление уже выполняется", Toast.LENGTH_SHORT).show(); return; }
        if (!TAG.matcher(tag).matches()) { Toast.makeText(act, "Непонятный номер релиза", Toast.LENGTH_LONG).show(); return; }
        running = true;
        cancel = false;
        wipe(act);
        showProgress("Скачивание " + tag);
        new Thread(() -> {
            try {
                String expected = fetchExpectedSha(tag);
                File part = new File(dir(act), "knothop-" + tag + ".apk.part");
                String got;
                try (FileOutputStream out = new FileOutputStream(part)) {
                    got = download(BASE + tag + "/knothop.apk", out, MAX_APK, true);
                }
                if (!got.equalsIgnoreCase(expected)) { part.delete(); throw new Refusal("Контрольная сумма файла не совпала с SHA256SUMS релиза. Файл удалён, ничего не установлено."); }
                File apk = new File(dir(act), "knothop-" + tag + ".apk");
                if (!part.renameTo(apk)) { part.delete(); throw new Refusal("Не удалось сохранить файл обновления"); }
                verifyPackage(apk);
                sp.edit().putString("upd_file", apk.getName()).putString("upd_sha", expected.toLowerCase(Locale.ROOT)).putString("upd_tag", tag).apply();
                ui.post(() -> { closeProgress(); askInstall(apk, tag); });
            } catch (Refusal r) {
                fail(r.getMessage());
            } catch (Exception e) {
                fail(cancel ? "Загрузка отменена" : "Не удалось скачать обновление: " + PhysNet.why(e));
            } finally {
                running = false;
            }
        }, "knothop-update").start();
    }

    private String fetchExpectedSha(String tag) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        download(BASE + tag + "/SHA256SUMS", b, MAX_SUMS, false);
        String text = new String(b.toByteArray(), StandardCharsets.UTF_8);
        for (String line : text.split("\n")) {
            String[] p = line.trim().split("\\s+");
            if (p.length == 2 && (p[1].equals("knothop.apk") || p[1].equals("*knothop.apk")) && HEX64.matcher(p[0]).matches()) return p[0];
        }
        throw new Refusal("В SHA256SUMS релиза " + tag + " нет строки knothop.apk. Обновление отменено.");
    }

    // ---- сеть

    private static boolean hostOk(String h) {
        return h != null && (h.equals("github.com") || h.endsWith(".github.com") || h.endsWith(".githubusercontent.com"));
    }

    /** HTTPS-соединение с ручными редиректами (до 5), каждый шаг - только https и только хосты GitHub. */
    private static HttpURLConnection open(String url) throws IOException {
        // сначала физическая сеть, при сетевой ошибке - обычный маршрут (через VPN): проверки адреса, суммы и подписи те же
        IOException last = null;
        for (int route = 0; route < PhysNet.routes(); route++) {
            try { return open(url, route); } catch (IOException e) { last = e; }
        }
        throw last != null ? last : new IOException("нет сети");
    }

    private static HttpURLConnection open(String url, int route) throws IOException {
        for (int i = 0; i <= 5; i++) {
            URL u = new URL(url);
            if (!"https".equals(u.getProtocol()) || !hostOk(u.getHost())) throw new IOException("небезопасный адрес");
            HttpURLConnection c = (HttpURLConnection) PhysNet.open(u, route);
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(15000);
            c.setReadTimeout(30000);
            c.setRequestProperty("User-Agent", "KnotHop-android");
            int code = c.getResponseCode();
            if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                String loc = c.getHeaderField("Location");
                c.disconnect();
                if (loc == null) throw new IOException("редирект без адреса");
                url = new URL(u, loc).toString();
                continue;
            }
            if (code != 200) { c.disconnect(); throw new IOException("сервер ответил " + code); }
            return c;
        }
        throw new IOException("слишком много редиректов");
    }

    /** Качает в `out`, считает SHA-256, режет по лимиту и по отмене. Возвращает hex хеша. */
    private String download(String url, OutputStream out, long max, boolean showProgress) throws Exception {
        HttpURLConnection c = open(url);
        try {
            long total = c.getContentLengthLong();
            if (total > max) throw new Refusal("Файл слишком велик (лимит " + (max >> 20) + " МБ). Обновление отменено.");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            InputStream in = c.getInputStream();
            byte[] buf = new byte[32768];
            long done = 0, lastUi = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                if (cancel) throw new IOException("отмена");
                done += n;
                if (done > max) throw new Refusal("Файл слишком велик (лимит " + (max >> 20) + " МБ). Обновление отменено.");
                md.update(buf, 0, n);
                out.write(buf, 0, n);
                long now = android.os.SystemClock.elapsedRealtime();
                if (showProgress && now - lastUi > 150) { lastUi = now; progress(done, total); }
            }
            if (total >= 0 && done != total) throw new IOException("файл получен не полностью");
            if (showProgress) progress(done, total);
            return hex(md.digest());
        } finally {
            c.disconnect();
        }
    }

    // ---- проверки пакета

    private static String hex(byte[] d) {
        StringBuilder s = new StringBuilder();
        for (byte b : d) s.append(String.format(Locale.ROOT, "%02x", b));
        return s.toString();
    }

    @SuppressWarnings("deprecation")
    private static Set<String> signers(PackageInfo pi) throws Exception {
        Signature[] sigs = null;
        if (Build.VERSION.SDK_INT >= 28 && pi.signingInfo != null) sigs = pi.signingInfo.getApkContentsSigners();
        if (sigs == null || sigs.length == 0) sigs = pi.signatures;
        if (sigs == null || sigs.length == 0) return null;
        Set<String> out = new HashSet<>();
        for (Signature s : sigs) out.add(hex(MessageDigest.getInstance("SHA-256").digest(s.toByteArray())));
        return out;
    }

    @SuppressWarnings("deprecation")
    private static long code(PackageInfo pi) {
        return Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : pi.versionCode;
    }

    @SuppressWarnings("deprecation")
    private void verifyPackage(File apk) throws Exception {
        PackageManager pm = act.getPackageManager();
        // Для файла часть прошивок (EMUI, Android 10) не заполняет signingInfo: просим оба поля, `signers` берёт любое заполненное
        int flags = PackageManager.GET_SIGNATURES | (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : 0);
        PackageInfo cand = pm.getPackageArchiveInfo(apk.getAbsolutePath(), flags);
        if (cand == null) throw new Refusal("Файл не является корректным APK. Обновление отменено.");
        if (!act.getPackageName().equals(cand.packageName)) throw new Refusal("Файл относится к другому приложению. Обновление отменено.");
        PackageInfo mine = pm.getPackageInfo(act.getPackageName(), flags);
        Set<String> a = signers(cand), b = signers(mine);
        // Система не отдала подпись файла: заранее сравнить нечем. Целостность уже проверена по SHA256SUMS тега, а обновление с другой подписью
        // отвергнет сам Android при установке (INSTALL_FAILED_UPDATE_INCOMPATIBLE). Прочитанная и несовпавшая подпись - отказ.
        if (a != null && (b == null || !a.equals(b))) throw new Refusal("Подпись скачанного файла не совпадает с подписью установленного приложения (возможно, другой ключ). Обновление отменено, ничего не установлено.");
        if (code(cand) <= code(mine)) throw new Refusal("В скачанном файле не более новая версия (" + code(cand) + ", у вас " + code(mine) + "). Обновление не требуется.");
    }

    // ---- диалоги

    private void showProgress(String title) {
        LinearLayout l = new LinearLayout(act);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(48, 24, 48, 0);
        label = new TextView(act);
        label.setText("Подключаюсь…");
        l.addView(label);
        bar = new ProgressBar(act, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(1000);
        bar.setIndeterminate(true);
        l.addView(bar);
        progress = new AlertDialog.Builder(act).setTitle(title).setView(l).setCancelable(false)
            .setNegativeButton("Отмена", (d, w) -> cancel = true).create();
        progress.show();
    }

    private void progress(final long done, final long total) {
        ui.post(() -> {
            if (progress == null || !progress.isShowing()) return;
            if (total > 0) {
                bar.setIndeterminate(false);
                bar.setProgress((int) (done * 1000 / total));
                label.setText(String.format(Locale.ROOT, "%.1f из %.1f МБ", done / 1e6, total / 1e6));
            } else {
                label.setText(String.format(Locale.ROOT, "%.1f МБ", done / 1e6));
            }
        });
    }

    private void closeProgress() {
        if (progress != null) { try { progress.dismiss(); } catch (Exception ignored) { } }
        progress = null;
    }

    private void fail(final String msg) {
        ui.post(() -> {
            closeProgress();
            forget();
            sp.edit().putString("upd_result", msg).apply();
            if (!act.isFinishing() && !act.isDestroyed())
                new AlertDialog.Builder(act).setTitle("Обновление не выполнено").setMessage(msg).setPositiveButton("OK", null).show();
        });
    }

    private void askInstall(final File apk, final String tag) {
        if (act.isFinishing() || act.isDestroyed()) return;
        new AlertDialog.Builder(act).setTitle("Установить " + tag + "?")
            .setMessage("Файл скачан и проверен: контрольная сумма совпала с SHA256SUMS релиза, подпись и пакет те же, версия новее.\n\n"
                + "Установка перезапускает приложение, VPN при этом прервётся: включите его заново после обновления. Профиль и права сохранятся.")
            .setPositiveButton("Установить", (d, w) -> beforeInstall(apk))
            .setNegativeButton("Отмена", (d, w) -> forget())
            .setOnCancelListener(d -> forget())
            .show();
    }

    private void beforeInstall(final File apk) {
        if (!act.getPackageManager().canRequestPackageInstalls()) {
            new AlertDialog.Builder(act).setTitle("Нужно разрешение")
                .setMessage("Android не позволяет приложению ставить обновления, пока вы не разрешите это в настройках («Установка неизвестных приложений» для KnotHop). "
                    + "Откроются настройки: включите переключатель и вернитесь назад, установка продолжится.")
                .setPositiveButton("Открыть настройки", (d, w) -> {
                    sp.edit().putBoolean("upd_wait_perm", true).apply();
                    try {
                        act.startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + act.getPackageName())));
                    } catch (Exception e) {
                        forget();
                        Toast.makeText(act, "Не удалось открыть настройки. Включите разрешение вручную и повторите", Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton("Отмена", (d, w) -> forget())
                .show();
            return;
        }
        install(apk);
    }

    /** Вызывается из onResume: после возврата из настроек разрешения повторно проверяем файл и продолжаем. */
    void resume() {
        String res = sp.getString("upd_result", "");
        if (!res.isEmpty()) sp.edit().remove("upd_result").apply();
        if (!sp.getBoolean("upd_wait_perm", false) || running) return;
        sp.edit().remove("upd_wait_perm").apply();
        final String name = sp.getString("upd_file", ""), sha = sp.getString("upd_sha", ""), tag = sp.getString("upd_tag", "");
        final File apk = new File(dir(act), name);
        if (name.isEmpty() || name.contains("/") || !apk.isFile() || !TAG.matcher(tag).matches() || !HEX64.matcher(sha).matches()) { forget(); return; }
        if (!act.getPackageManager().canRequestPackageInstalls()) {
            forget();
            Toast.makeText(act, "Разрешение не выдано, обновление отменено", Toast.LENGTH_LONG).show();
            return;
        }
        running = true;
        new Thread(() -> {
            try {
                String got = fileSha(apk);
                if (!got.equalsIgnoreCase(sha)) throw new Refusal("Файл обновления изменился. Обновление отменено.");
                verifyPackage(apk);
                ui.post(() -> askInstall(apk, tag));
            } catch (Refusal r) {
                fail(r.getMessage());
            } catch (Exception e) {
                fail("Не удалось проверить файл обновления: " + e.getClass().getSimpleName());
            } finally {
                running = false;
            }
        }, "knothop-update-resume").start();
    }

    private static String fileSha(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[32768];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        return hex(md.digest());
    }

    // ---- установка через PackageInstaller

    private void install(final File apk) {
        showProgress("Передаю системе");
        bar.setIndeterminate(true);
        label.setText("Готовлю установку…");
        progress.getButton(AlertDialog.BUTTON_NEGATIVE).setVisibility(View.GONE);
        new Thread(() -> {
            PackageInstaller pi = act.getPackageManager().getPackageInstaller();
            int id = -1;
            try {
                PackageInstaller.SessionParams sp0 = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
                sp0.setAppPackageName(act.getPackageName());
                id = pi.createSession(sp0);
                PackageInstaller.Session s = pi.openSession(id);
                try {
                    try (InputStream in = new FileInputStream(apk); OutputStream out = s.openWrite("knothop.apk", 0, apk.length())) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                        s.fsync(out);
                    }
                    // Явный получатель (не exported); FLAG_MUTABLE нужен PackageInstaller с API 31, чтобы система дописала статус в интент.
                    Intent cb = new Intent(act, UpdateInstallReceiver.class).setAction(ACTION_RESULT);
                    int fl = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
                    PendingIntent p = PendingIntent.getBroadcast(act, id, cb, fl);
                    s.commit(p.getIntentSender());
                } finally {
                    s.close();
                }
                ui.post(() -> {
                    closeProgress();
                    Toast.makeText(act, "Подтвердите установку в окне системы", Toast.LENGTH_LONG).show();
                });
            } catch (Exception e) {
                if (id >= 0) { try { pi.abandonSession(id); } catch (Exception ignored) { } }
                fail("Не удалось передать файл установщику: " + e.getClass().getSimpleName());
            }
        }, "knothop-update-install").start();
    }

    /** Итог установки от системы (из {@link UpdateInstallReceiver}). Успех обычно не доходит: процесс заменяется. */
    static void onResult(Context c, int status, String sysMsg) {
        String text;
        switch (status) {
            case PackageInstaller.STATUS_SUCCESS: text = "Обновление установлено. Включите VPN заново."; break;
            case PackageInstaller.STATUS_FAILURE_ABORTED: text = "Установка отменена."; break;
            case PackageInstaller.STATUS_FAILURE_CONFLICT: text = "Установка не удалась: конфликт с установленной версией (другая подпись?)."; break;
            case PackageInstaller.STATUS_FAILURE_INCOMPATIBLE: text = "Установка не удалась: файл несовместим с этим телефоном."; break;
            case PackageInstaller.STATUS_FAILURE_STORAGE: text = "Установка не удалась: не хватает места."; break;
            case PackageInstaller.STATUS_FAILURE_BLOCKED: text = "Установка заблокирована системой или политикой телефона."; break;
            default:
                String m = sysMsg == null ? "" : sysMsg.replaceAll("[^\\x20-\\x7E]", "?");
                if (m.length() > 120) m = m.substring(0, 120);
                text = "Установка не удалась" + (m.isEmpty() ? "." : ": " + m);
        }
        wipe(c);
        SharedPreferences p = c.getSharedPreferences("p", Context.MODE_PRIVATE);
        p.edit().remove("upd_file").remove("upd_sha").remove("upd_tag").remove("upd_wait_perm").putString("upd_result", text).apply();
        Toast.makeText(c, text, Toast.LENGTH_LONG).show();
    }
}
