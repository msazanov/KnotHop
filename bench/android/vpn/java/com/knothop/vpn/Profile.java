package com.knothop.vpn;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** Локальная identity/Trust 0013 и приглашение kh- (v4, ADR 0019). Приватный ключ не импортируется из профиля. */
final class Profile {
    final String raw;

    /** Срок приглашения, как enroll::TTL в enroll.rs (48 ч). Срок и права видны только в подписанном предложении ноды. */
    static final long INVITE_TTL_S = 48L * 3600;
    /** Число нод приглашения (1..8). Права, корень и срок в строке не хранятся: их показывает нода после проверки подписи. */
    int nodeCount;

    /** Пустой профиль = «своя сеть»: приглашения нет, телефон сам себе админ (anchor свой). OWN - то же, для уже настроенных. */
    static final String OWN = "own";
    /** Ссылка из QR приглашения: KnotHop://i/ + хвост строки после kh-. */
    static final String LINK = "knothop://i/";

    /** R-3: приглашение принято и погашено; pin больше не хранится ни в настройках, ни в state/profile.txt. Приглашения в этом профиле нет. */
    static final String ENROLLED = "enrolled";
    /** Зачисление завершено (профиль без приглашения, но не «своя сеть»). */
    boolean enrolled;

    boolean own() {
        return raw.isEmpty() && !enrolled;
    }

    private Profile(String raw) { this.raw = raw; }

    /** Разбор с проверкой префикса и контрольной суммы. Бросает исключение с понятным текстом. */
    static Profile parse(String text) throws Exception {
        if (text.length() > 4096) throw new Exception("приглашение слишком длинное");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!Character.isWhitespace(c)) sb.append(c);
        }
        String s = sb.toString();
        // QR несёт ссылку KnotHop://i/<хвост>: по ней камера телефона открывает приложение; это то же приглашение kh-<хвост>
        if (s.startsWith(LINK)) s = "kh-" + s.substring(LINK.length());
        if (s.isEmpty() || s.equals(OWN)) return new Profile("");
        if (s.equals(ENROLLED)) {
            Profile pr = new Profile("");
            pr.enrolled = true;
            return pr;
        }
        if (s.startsWith("kh-")) return parseInvite(s);
        throw new Exception("это не профиль KnotHop (нужно приглашение kh-base64 или QR)");
    }

    /**
     * kh- (v4): base64url без «=» от n x identity-хеш ноды(16), n=1..8, по возрастанию без повторов | pin(24, не нулевой) | sha256("knothop-invite-v4" + всё до суммы)[..4].
     * Длина хвоста 59..208 символов. Версии 1-3 не принимаются. Pin нативная часть читает сама; здесь только разбор и число нод.
     */
    private static Profile parseInvite(String s) throws Exception {
        String tail = s.substring(3);
        if (tail.length() > 208) throw new Exception("версия приглашения не поддерживается: нужно приглашение v4");
        byte[] b;
        try {
            b = Base64.decode(tail, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new Exception("в строке есть лишние символы");
        }
        if (b.length < 44 || b.length > 156 || (b.length - 28) % 16 != 0) throw new Exception("версия приглашения не поддерживается: нужно приглашение v4");
        int n = (b.length - 28) / 16;
        byte[] body = Arrays.copyOf(b, b.length - 4);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("knothop-invite-v4".getBytes(StandardCharsets.US_ASCII));
        byte[] sum = md.digest(body);
        int diff = 0;
        for (int i = 0; i < 4; i++) diff |= sum[i] ^ b[b.length - 4 + i];
        if (diff != 0) throw new Exception("контрольная сумма не сошлась: строка повреждена при копировании");
        for (int i = 1; i < n; i++) {
            if (compare(body, 16 * (i - 1), 16 * i) >= 0) throw new Exception("приглашение повреждено (порядок нод)");
        }
        int zero = 0;
        for (int i = 16 * n; i < 16 * n + 24; i++) zero |= body[i];
        if (zero == 0) throw new Exception("приглашение повреждено (pin)");
        Profile pr = new Profile(s);
        pr.nodeCount = n;
        return pr;
    }

    /** Побайтовое сравнение 16-байтовых блоков как беззнаковых (так же сортирует Rust). */
    private static int compare(byte[] b, int x, int y) {
        for (int i = 0; i < 16; i++) {
            int d = (b[x + i] & 0xff) - (b[y + i] & 0xff);
            if (d != 0) return d;
        }
        return 0;
    }
}
