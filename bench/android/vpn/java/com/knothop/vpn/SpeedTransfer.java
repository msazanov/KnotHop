package com.knothop.vpn;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/** HTTP payload only; no RNS messages, files or native benchmark. One bounded direction. */
final class SpeedTransfer {
    static final long MAX_BYTES = 25_000_000;
    static final int MAX_MS = 15_000;
    static final String DOWN = "https://speed.cloudflare.com/__down?bytes={bytes}";
    static final String UP = "https://speed.cloudflare.com/__up";
    interface Connection { HttpURLConnection open(URL url) throws Exception; }

    static URL endpoint(String text, long bytes) throws Exception {
        if (text.length() > 2048) throw new IOException("Адрес слишком длинный");
        URL url = new URL(text.trim().replace("{bytes}", Long.toString(bytes)));
        if (!("https".equals(url.getProtocol()) || "http".equals(url.getProtocol()))
                || url.getHost().isEmpty() || url.getUserInfo() != null || url.getRef() != null)
            throw new IOException("Нужен HTTP(S) URL без пароля и фрагмента");
        return url;
    }

    static final class Result {
        final long bytes, nanos;
        final boolean limited;
        Result(long bytes, long nanos, boolean limited) {
            this.bytes = bytes; this.nanos = Math.max(1, nanos); this.limited = limited;
        }
        String text() {
            return String.format(Locale.ROOT, "%.2f Мбит/с · %.2f МБ · %.2f с%s",
                    bytes * 8000.0 / nanos, bytes / 1e6, nanos / 1e9, limited ? " (лимит)" : "");
        }
    }

    static Result run(Connection factory, BooleanSupplier valid, String endpoint, boolean upload,
                      long limit, int millis) throws Exception {
        if (limit < 1 || limit > MAX_BYTES || millis < 1 || millis > MAX_MS)
            throw new IOException("Превышен лимит теста");
        if (!valid.getAsBoolean()) throw new IOException("VPN не подключён");
        URL url = endpoint(endpoint, limit);
        HttpURLConnection c = factory.open(url);
        ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor();
        long start = System.nanoTime(), count = 0;
        long deadline = start + millis * 1_000_000L;
        try {
            c.setConnectTimeout(millis);
            c.setReadTimeout(millis);
            c.setUseCaches(false);
            c.setInstanceFollowRedirects(false); // Never change network/target behind the user's back.
            c.setRequestProperty("Accept-Encoding", "identity");
            c.setRequestProperty("Cache-Control", "no-store");
            watchdog.scheduleAtFixedRate(() -> {
                if (System.nanoTime() >= deadline || !valid.getAsBoolean()) c.disconnect();
            }, 0, 100, TimeUnit.MILLISECONDS);
            if (upload) {
                c.setRequestMethod("POST");
                c.setDoOutput(true);
                c.setFixedLengthStreamingMode(limit);
                c.setRequestProperty("Content-Type", "application/octet-stream");
                byte[] block = new byte[32 * 1024];
                new java.security.SecureRandom().nextBytes(block);
                try (OutputStream out = c.getOutputStream()) {
                    while (count < limit) {
                        if (!valid.getAsBoolean() || System.nanoTime() >= deadline) throw new IOException("Тест прерван");
                        int n = (int)Math.min(block.length, limit - count);
                        out.write(block, 0, n);
                        count += n;
                    }
                }
                int code = c.getResponseCode();
                if (code < 200 || code >= 300) throw new IOException("HTTP " + code);
                // Publish upload speed only once the server acknowledged the complete body.
            } else {
                int code = c.getResponseCode();
                if (code != 200) throw new IOException("HTTP " + code);
                String encoding = c.getContentEncoding();
                if (encoding != null && !encoding.equalsIgnoreCase("identity")) throw new IOException("Ответ сжат");
                long expected = c.getContentLengthLong();
                try (InputStream in = c.getInputStream()) {
                    byte[] block = new byte[32 * 1024];
                    while (count < limit && System.nanoTime() < deadline) {
                        if (!valid.getAsBoolean()) throw new IOException("VPN отключён или сменился");
                        int n = in.read(block, 0, (int)Math.min(block.length, limit - count));
                        if (n < 0) {
                            if (expected >= 0 && count != expected) throw new IOException("Неполный HTTP ответ");
                            break;
                        }
                        count += n;
                    }
                }
            }
            if (!valid.getAsBoolean()) throw new IOException("VPN отключён или сменился");
            if (count == 0) throw new IOException("Нет данных");
            return new Result(count, System.nanoTime() - start, count == limit || System.nanoTime() >= deadline);
        } catch (IOException e) {
            long elapsed = System.nanoTime() - start;
            if (!upload && count > 0 && valid.getAsBoolean() && System.nanoTime() >= deadline)
                return new Result(count, elapsed, true);
            // An interrupted upload only counts writes to the local socket, not acknowledged throughput.
            throw new IOException(e.getMessage() + String.format(Locale.ROOT,
                    " · %.2f МБ %s · %.2f с", count / 1e6,
                    upload ? "записано в сокет (не подтверждено)" : "прочитано", elapsed / 1e9), e);
        } finally {
            watchdog.shutdownNow();
            c.disconnect();
        }
    }
}
