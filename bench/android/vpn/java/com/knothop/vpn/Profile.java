package com.knothop.vpn;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Строка приглашения ADR 0028 §2.1: base64url без «=» и без префикса, тело ver(1)=1 | n(1)=1..8 | n x [хеш ноды(16) | pin(16)] | ck(4),
 * ck = sha256("knothop-invite-v5" + тело)[..4]. Права, срок и ключи в строке не лежат. Пины нативная часть читает сама; здесь только разбор,
 * число нод и проверка опечаток. Старые форматы (kh-, khs-) не принимаются.
 */
final class Profile {
    final String raw;
    /** Число нод приглашения (1..8). */
    int nodeCount;
    /** Приглашение уже погашено и стёрто: профиль «в сети». */
    boolean enrolled;

    /** Пустой профиль = «своя сеть»: приглашения нет, телефон сам выпускает приглашения. */
    static final String OWN = "own";
    /** Погашено полностью (pin больше нигде не хранится). */
    static final String ENROLLED = "enrolled";
    /** Ссылка из QR/обёртки ОС: knothop://i/<строка>. */
    static final String LINK = "knothop://i/";
    static final int MAX_CHARS = 4096;

    boolean own() { return raw.isEmpty() && !enrolled; }

    private Profile(String raw) { this.raw = raw; }

    static Profile parse(String text) throws Exception {
        if (text.length() > MAX_CHARS) throw new Exception("приглашение слишком длинное");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!Character.isWhitespace(c)) sb.append(c);
        }
        String s = sb.toString();
        if (s.startsWith(LINK)) s = s.substring(LINK.length());
        if (s.isEmpty() || s.equals(OWN)) return new Profile("");
        if (s.equals(ENROLLED)) {
            Profile pr = new Profile("");
            pr.enrolled = true;
            return pr;
        }
        if (s.startsWith("kh-") || s.startsWith("khs-")) throw new Exception("старый формат приглашения (kh-/khs-) больше не поддерживается: нужно новое");
        return parseInvite(s);
    }

    private static Profile parseInvite(String s) throws Exception {
        byte[] b;
        try {
            b = Base64.decode(s, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new Exception("в строке есть лишние символы");
        }
        if (b.length < 2 + 32 + 4 || b[0] != 1) throw new Exception("это не приглашение KnotHop (версия или длина)");
        int n = b[1] & 0xff;
        if (n < 1 || n > 8 || b.length != 2 + 32 * n + 4) throw new Exception("приглашение повреждено (число нод)");
        byte[] body = Arrays.copyOf(b, b.length - 4);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("knothop-invite-v5".getBytes(StandardCharsets.US_ASCII));
        byte[] sum = md.digest(body);
        int diff = 0;
        for (int i = 0; i < 4; i++) diff |= sum[i] ^ b[b.length - 4 + i];
        if (diff != 0) throw new Exception("контрольная сумма не сошлась: строка повреждена при копировании");
        for (int i = 0; i < n; i++) {
            if (i > 0 && compare(body, 2 + 32 * (i - 1), 2 + 32 * i) >= 0) throw new Exception("приглашение повреждено (порядок нод)");
            int zero = 0;
            for (int j = 0; j < 16; j++) zero |= body[2 + 32 * i + 16 + j];
            if (zero == 0) throw new Exception("приглашение повреждено (pin)");
        }
        Profile pr = new Profile(s);
        pr.nodeCount = n;
        return pr;
    }

    /** Хеш i-й ноды строки (hex) - для диалога подтверждения. */
    String nodeHash(int i) {
        byte[] b = Base64.decode(raw, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        StringBuilder h = new StringBuilder();
        for (int j = 0; j < 16; j++) h.append(String.format("%02x", b[2 + 32 * i + j]));
        return h.toString();
    }

    private static int compare(byte[] b, int x, int y) {
        for (int i = 0; i < 16; i++) {
            int d = (b[x + i] & 0xff) - (b[y + i] & 0xff);
            if (d != 0) return d;
        }
        return 0;
    }
}
