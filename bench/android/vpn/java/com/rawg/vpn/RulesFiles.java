package com.rawg.vpn;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;

/**
 * Файлы списков geoip.dat и geosite.dat проекта runetfreedom/russia-v2ray-rules-dat (обновляется раз в 6 часов).
 * Скачиваются приложением напрямую (само приложение исключено из туннеля), проверяются по sha256 из релиза и кладутся в files/rules.
 * Содержимое недоверенное: разбирает его нативная часть с ограничением размеров.
 */
final class RulesFiles {
    static final String[] NAMES = {"geoip.dat", "geosite.dat"};
    private static final String[] BASES = {
            "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/",
            "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/"};
    private static final long MAX_BYTES = 200L << 20;

    interface Progress { void on(String text); }

    static File dir(File filesDir) { return new File(filesDir, "rules"); }

    static boolean present(File filesDir) {
        for (String n : NAMES) if (!new File(dir(filesDir), n).isFile()) return false;
        return true;
    }

    /** Скачать оба файла; возвращает пустую строку при успехе, иначе причину. Вызывать не из главного потока. */
    static String download(File filesDir, Progress p) {
        File d = dir(filesDir);
        d.mkdirs();
        for (String name : NAMES) {
            String want = null;
            for (String b : BASES) {
                want = fetchSum(b + name + ".sha256sum");
                if (want != null) break;
            }
            String err = "";
            boolean ok = false;
            for (String b : BASES) {
                File part = new File(d, name + ".part");
                try {
                    String got = get(b + name, part, name, p);
                    if (want != null && !want.equals(got)) throw new Exception("не сошлась контрольная сумма");
                    Files.move(part.toPath(), new File(d, name).toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                    ok = true;
                    break;
                } catch (Throwable t) {
                    err = name + ": " + t.getMessage();
                    part.delete();
                }
            }
            if (!ok) return err;
        }
        return "";
    }

    private static String fetchSum(String url) {
        try {
            HttpURLConnection c = open(url);
            if (c.getResponseCode() != 200) return null;
            try (InputStream in = c.getInputStream()) {
                byte[] b = new byte[256];
                int n = in.read(b);
                String t = new String(b, 0, Math.max(n, 0), "UTF-8").trim();
                String h = t.split("\\s+")[0].toLowerCase();
                return h.matches("[0-9a-f]{64}") ? h : null;
            }
        } catch (Throwable t) {
            return null;
        }
    }

    private static HttpURLConnection open(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(30000);
        c.setRequestProperty("User-Agent", "rawg-vpn");
        return c;
    }

    private static String get(String url, File to, String name, Progress p) throws Exception {
        HttpURLConnection c = open(url);
        if (c.getResponseCode() != 200) throw new Exception("HTTP " + c.getResponseCode());
        long total = c.getContentLengthLong();
        if (total > MAX_BYTES) throw new Exception("файл слишком большой");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        long got = 0, shown = 0;
        try (InputStream in = c.getInputStream(); OutputStream out = new FileOutputStream(to)) {
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) {
                got += n;
                if (got > MAX_BYTES) throw new Exception("файл слишком большой");
                md.update(buf, 0, n);
                out.write(buf, 0, n);
                if (got - shown >= (512 << 10)) {
                    shown = got;
                    p.on(name + ": " + (got >> 20) + (total > 0 ? " из " + (total >> 20) : "") + " МБ");
                }
            }
        }
        if (total > 0 && got != total) throw new Exception("файл скачан не полностью");
        StringBuilder h = new StringBuilder();
        for (byte x : md.digest()) h.append(String.format("%02x", x));
        return h.toString();
    }
}
