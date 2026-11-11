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

    /**
     * Тег последнего релиза. Сначала без API: `github.com/.../releases/latest` отвечает редиректом на страницу тега (в «latest» не
     * попадают черновики и пре-релизы). API - запасной путь: у него лимит 60 запросов в час на адрес, а за NAT оператора адрес общий
     * на тысячи абонентов (ответ 403), и api.github.com бывает недоступен отдельно от github.com. Каждый способ пробуется по
     * физической сети, затем по обычному маршруту (через VPN).
     */
    static Result fetch() {
        Result last = new Result(0, "", "нет сети");
        for (int route = 0; route < PhysNet.routes(); route++) {
            Result r = viaRedirect(route);
            if (r.error == null) return r;
            last = r;
            r = viaApi(route);
            if (r.error == null) return r;
            last = r;
        }
        return last;
    }

    static final String LATEST = "https://github.com/msazanov/KnotHop/releases/latest";
    private static final String TAG_PATH = "/msazanov/KnotHop/releases/tag/";

    /** Тег из адреса редиректа `.../releases/tag/<тег>`; "" - адрес не того вида (чужой хост, не https, другой путь). */
    static String tagFromLocation(String loc) {
        try {
            URL u = new URL(new URL(LATEST), loc);
            if (!"https".equals(u.getProtocol()) || !"github.com".equals(u.getHost())) return "";
            String p = u.getPath();
            if (!p.startsWith(TAG_PATH)) return "";
            String tag = p.substring(TAG_PATH.length());
            if (tag.isEmpty() || tag.length() > 32 || tag.indexOf('/') >= 0) return "";
            return tag;
        } catch (Exception e) {
            return "";
        }
    }

    private static Result viaRedirect(int route) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) PhysNet.open(new URL(LATEST), route);
            c.setInstanceFollowRedirects(false);
            c.setRequestMethod("HEAD");
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            c.setRequestProperty("User-Agent", "KnotHop-android");
            int code = c.getResponseCode();
            if (code != 301 && code != 302 && code != 303 && code != 307 && code != 308) return new Result(0, "", "GitHub ответил " + code);
            String tag = tagFromLocation(String.valueOf(c.getHeaderField("Location")));
            long num = number(tag);
            if (num <= 0) return new Result(0, tag, "непонятный номер релиза");
            return new Result(num, tag, null);
        } catch (Exception e) {
            return new Result(0, "", PhysNet.why(e));
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static Result viaApi(int route) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) PhysNet.open(new URL(API), route);
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            c.setRequestProperty("Accept", "application/vnd.github+json");
            c.setRequestProperty("User-Agent", "KnotHop-android");
            int code = c.getResponseCode();
            if (code == 403 || code == 429) return new Result(0, "", "GitHub ограничил число запросов с этого адреса, попробуйте позже");
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
            return new Result(0, "", PhysNet.why(e));
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
