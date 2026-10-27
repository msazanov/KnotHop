package com.knothop.vpn;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Проверка свежего релиза на GitHub (один запрос к API, только HTTPS). Работает в фоновом потоке, UI не блокирует.
 * Установку не делает: пользователю предлагается скачать APK, а систему обновления подписи защищает сам Android
 * (чужая подпись поверх не встанет).
 */
final class UpdateCheck {
    static final String API = "https://api.github.com/repos/msazanov/KnotHop/releases/latest";
    static final String APK = "https://github.com/msazanov/KnotHop/releases/latest/download/knothop.apk";
    private static final int MAX_BYTES = 256 * 1024;

    /** Итог проверки: либо ошибка, либо номер последнего релиза (versionCode совпадает с номером запуска CI, тег v0.1.N). */
    static final class Result {
        final long latest;
        final String tag;
        final String error;
        Result(long latest, String tag, String error) { this.latest = latest; this.tag = tag; this.error = error; }
    }

    interface Callback { void done(Result r); }

    /** Запускает проверку в отдельном потоке; `cb` вызывается из этого потока (переход в UI - дело вызывающего). */
    static void run(final Callback cb) {
        Thread t = new Thread(new Runnable() {
            public void run() { cb.done(fetch()); }
        }, "knothop-update-check");
        t.setDaemon(true);
        t.start();
    }

    static Result fetch() {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(API).openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            c.setRequestProperty("Accept", "application/vnd.github+json");
            c.setRequestProperty("User-Agent", "KnotHop-android");
            int code = c.getResponseCode();
            if (code != 200) return new Result(0, "", "GitHub ответил " + code);
            InputStream in = c.getInputStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > MAX_BYTES) return new Result(0, "", "ответ слишком велик");
            }
            JSONObject o = new JSONObject(new String(out.toByteArray(), StandardCharsets.UTF_8));
            if (o.optBoolean("draft") || o.optBoolean("prerelease")) return new Result(0, "", "последний релиз не опубликован как стабильный");
            String tag = o.optString("tag_name", "");
            long num = number(tag);
            if (num <= 0) return new Result(0, tag, "непонятный номер релиза: " + (tag.length() > 24 ? tag.substring(0, 24) : tag));
            return new Result(num, tag, null);
        } catch (Exception e) {
            return new Result(0, "", e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()));
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /** `v0.1.12` -> 12: последняя числовая часть тега. 0, если тег не такого вида. */
    static long number(String tag) {
        int i = tag.lastIndexOf('.');
        String s = i < 0 ? "" : tag.substring(i + 1);
        if (s.length() == 0 || s.length() > 9) return 0;
        for (int k = 0; k < s.length(); k++) if (s.charAt(k) < '0' || s.charAt(k) > '9') return 0;
        return Long.parseLong(s);
    }
}
