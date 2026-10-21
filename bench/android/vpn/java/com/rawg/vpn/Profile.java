package com.rawg.vpn;

import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Профили клиента. Строка rawg2-/rawg3-<base64url(бинарный формат)>, в конце sha256[..4] от тела.
 * v2: версия(1)=2 | seed(32) | ip(4) | len+группа | n | n x [len+имя | d(16) | k(32) | m |
 *     m x (тип 4|6: ip, порт | тип 3: len+"имя:порт")].
 * v3 (модель 0012): версия(1)=3 | seed(32) | ip(4) | len+группа | admin(64) | грамота(80) | подпись(64) |
 *     table_ver(8) | payload таблицы (ver(8) | n | n x [записи как в v2]) | подпись таблицы(64).
 * Профиль - секрет целиком (в v3 внутри ещё и грамота с seed'ом клиента). Разбор здесь нужен только
 * экрану (группа, адрес, серверы); подписи и ключи проверяет нативная часть.
 */
final class Profile {
    final String raw;
    final String group;
    final String ip;
    final int servers;
    final String firstServer;
    /** true - профиль v3 (модель 0012, грамота от админа вместо привязки по секрету сервера). */
    final boolean v3;
    /** Номер подписанной таблицы выходов, вшитой в профиль (0 - приедет позже по T_SVT). */
    final long tableVer;

    /** true - приглашение rawgi- (модель 0013, формат v3): ключ клиент создаёт сам, в строке публичный ключ приглашающего и одноразовый pin. */
    final boolean invite;

    /** Срок приглашения, как INVITE_TTL_S в trust.rs (30 дней). Экран подтверждения показывает его; проверяет нативная часть. */
    static final long INVITE_TTL_S = 30L * 24 * 3600;
    /** Поля приглашения для экрана подтверждения (заполняются в parseInvite; пин сюда не попадает). */
    String inviterHash = "";
    /** Корень сети: у своего приглашения совпадает с приглашающим, у делегированного - отдельный ключ корня. */
    String rootHash = "";
    boolean delegated;
    int rights;
    long created;
    int nodeCount;

    /** Пустой профиль = «своя сеть»: приглашения нет, телефон сам себе админ (anchor свой). OWN - то же, для уже настроенных. */
    static final String OWN = "own";
    /** Ссылка из QR приглашения: rawg://i/ + хвост строки после rawgi-. */
    static final String LINK = "rawg://i/";

    boolean own() {
        return invite && raw.isEmpty();
    }

    private Profile(String raw, String group, String ip, int servers, String first, boolean v3, long tableVer) {
        this(raw, group, ip, servers, first, v3, tableVer, false);
    }

    private Profile(String raw, String group, String ip, int servers, String first, boolean v3, long tableVer, boolean invite) {
        this.invite = invite;
        this.raw = raw;
        this.group = group;
        this.ip = ip;
        this.servers = servers;
        this.firstServer = first;
        this.v3 = v3;
        this.tableVer = tableVer;
    }

    /** Разбор с проверкой префикса и контрольной суммы. Бросает исключение с понятным текстом. */
    static Profile parse(String text) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!Character.isWhitespace(c)) sb.append(c);
        }
        String s = sb.toString();
        // QR несёт ссылку rawg://i/<хвост>: по ней камера телефона открывает приложение; это то же приглашение rawgi-<хвост>
        if (s.startsWith(LINK)) s = "rawgi-" + s.substring(LINK.length());
        // приглашение эмодзи: разбор и проверка суммы в нативном ядре, дальше - обычная строка rawgi-
        if (!s.isEmpty() && s.charAt(0) > 127) {
            String b = Native.toBase64(s);
            if (b == null || b.isEmpty()) throw new Exception("эмодзи-строка не распознана как приглашение (не хватает символов или они искажены)");
            s = b;
        }
        if (s.isEmpty() || s.equals(OWN)) return new Profile("", "своя сеть", "", 0, "", false, 0, true);
        if (s.startsWith("rawgi-")) return parseInvite(s);
        if (s.startsWith("rawg3-")) return parseV3(s);
        if (s.startsWith("rawg2-")) return parseV2(s);
        throw new Exception("это не профиль rawg (нужен префикс rawgi-, rawg2- или rawg3-)");
    }

    /**
     * rawgi- (v3): v(1)=3 | flags(1) bit0=delegated | приглашающий(64) | [корень(64), только при delegated] | pin(16) | rights(2 LE) |
     * created(8 BE) | n(1) x [len(1) + адрес], n<=4 | m(1) x identity-хеш ноды(16), m<=8, без повторов | sha256[..4].
     * Подписи, MAC и срок проверяет нативная часть; здесь только разбор и поля для экрана. Версии 1 и 2 не принимаются.
     */
    private static Profile parseInvite(String s) throws Exception {
        byte[] body = ck(b64(s.substring(6)));
        if ((body[0] & 0xff) != 3) throw new Exception("версия приглашения не поддерживается");
        if ((body[1] & ~1) != 0) throw new Exception("приглашение повреждено (флаги)");
        boolean delegated = (body[1] & 1) != 0;
        need(body, 2, 64);
        byte[] inviter = Arrays.copyOfRange(body, 2, 66);
        int p = 66;
        byte[] root = inviter;
        if (delegated) {
            need(body, p, 64);
            root = Arrays.copyOfRange(body, p, p + 64);
            p += 64;
            // делегирование от самого себя не бывает: такое приглашение подделано или повреждено
            if (Arrays.equals(idHash(root), idHash(inviter))) throw new Exception("приглашение повреждено (корень совпадает с приглашающим)");
        }
        // pin (16) не читаем: им владеет нативная часть; дальше rights(2), created(8), n(1)
        need(body, p, 16 + 2 + 8 + 1);
        p += 16;
        int rights = (body[p] & 0xff) | ((body[p + 1] & 0xff) << 8);
        p += 2;
        if ((rights & ~63) != 0) throw new Exception("приглашение повреждено (права)");
        long created = 0;
        for (int i = 0; i < 8; i++) created = (created << 8) | (body[p + i] & 0xffL);
        p += 8;
        int n = body[p++] & 0xff;
        if (n > 4) throw new Exception("приглашение повреждено (адреса)");
        String first = "";
        for (int i = 0; i < n; i++) {
            need(body, p, 1);
            int l = body[p++] & 0xff;
            if (l > 200) throw new Exception("приглашение повреждено (адрес)");
            need(body, p, l);
            if (i == 0) first = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(body, p, l)).toString();
            p += l;
        }
        // входные ноды: 0..8 identity-хешей по 16 байт; 0 значит «любая нода корня». Повтор - признак подделки
        need(body, p, 1);
        int nodeCount = body[p++] & 0xff;
        if (nodeCount > 8) throw new Exception("приглашение повреждено (число нод)");
        need(body, p, 16 * nodeCount);
        for (int i = 0; i < nodeCount; i++) {
            byte[] h = Arrays.copyOfRange(body, p + 16 * i, p + 16 * i + 16);
            for (int k = 0; k < i; k++) {
                if (Arrays.equals(h, Arrays.copyOfRange(body, p + 16 * k, p + 16 * k + 16))) throw new Exception("приглашение повреждено (повтор ноды)");
            }
        }
        p += 16 * nodeCount;
        if (p != body.length) throw new Exception("приглашение повреждено (длина)");
        Profile pr = new Profile(s, "приглашение", "", n, first, false, 0, true);
        pr.inviterHash = hexOf(idHash(inviter), 16);
        pr.rootHash = delegated ? hexOf(idHash(root), 16) : pr.inviterHash;
        pr.delegated = delegated;
        pr.rights = rights;
        pr.created = created;
        pr.nodeCount = nodeCount;
        return pr;
    }

    /** identity-хеш ключа ядра: sha256(pub 64 Б)[..16], как Identity::hash / hash_of в trust.rs. */
    private static byte[] idHash(byte[] pub) throws Exception {
        return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(pub), 16);
    }

    /** Проверка, что в теле есть хотя бы n байт с позиции p; иначе приглашение обрезано. */
    private static void need(byte[] body, int p, int n) throws Exception {
        if (p < 0 || n < 0 || p + n > body.length) throw new Exception("приглашение повреждено (короткое)");
    }

    /** Первые n байт в hex (строчными). */
    static String hexOf(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i] & 0xff));
        return sb.toString();
    }

    private static byte[] b64(String tail) throws Exception {
        try {
            return Base64.decode(tail, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new Exception("в строке есть лишние символы");
        }
    }

    /** Тело без последних 4 байт; сверяем контрольную сумму sha256[..4]. */
    private static byte[] ck(byte[] b) throws Exception {
        if (b.length < 12) throw new Exception("профиль слишком короткий");
        byte[] body = Arrays.copyOf(b, b.length - 4);
        byte[] sum = MessageDigest.getInstance("SHA-256").digest(body);
        for (int i = 0; i < 4; i++) {
            if (sum[i] != b[b.length - 4 + i]) throw new Exception("контрольная сумма не сошлась: строка повреждена при копировании");
        }
        return body;
    }

    private static String dotted(byte[] body, int p) {
        return (body[p] & 0xff) + "." + (body[p + 1] & 0xff) + "." + (body[p + 2] & 0xff) + "." + (body[p + 3] & 0xff);
    }

    private static long le64(byte[] body, int p) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (body[p + i] & 0xffL);
        return v;
    }

    private static Profile parseV2(String s) throws Exception {
        byte[] body = ck(b64(s.substring(6)));
        int p = 0;
        if ((body[p++] & 0xff) != 2) throw new Exception("версия профиля не поддерживается");
        p += 32;
        String ip = dotted(body, p);
        p += 4;
        int gl = body[p++] & 0xff;
        if (gl == 0) throw new Exception("профиль повреждён (группа)");
        String group = new String(body, p, gl, "UTF-8");
        p += gl;
        int n = body[p++] & 0xff;
        String first = "";
        for (int i = 0; i < n; i++) {
            int nl = body[p++] & 0xff;
            String name = new String(body, p, nl, "UTF-8");
            if (i == 0) first = name;
            p += nl + 16 + 32;
            int m = body[p++] & 0xff;
            for (int k = 0; k < m; k++) {
                int t = body[p++] & 0xff;
                if (t == 3) p += 1 + (body[p] & 0xff);          // имя:порт текстом
                else p += (t == 4 ? 4 : 16) + 2;
            }
        }
        if (p != body.length) throw new Exception("профиль повреждён (длина)");
        return new Profile(s, group, ip, n, first, false, 0);
    }

    private static Profile parseV3(String s) throws Exception {
        byte[] body = ck(b64(s.substring(6)));
        int p = 0;
        if ((body[p++] & 0xff) != 3) throw new Exception("версия профиля не поддерживается");
        p += 32;                                   // seed клиента (секрет, ключи растит только нативная часть)
        String ip = dotted(body, p);
        p += 4;
        int gl = body[p++] & 0xff;
        if (gl == 0) throw new Exception("профиль повреждён (группа)");
        String group = new String(body, p, gl, "UTF-8");
        p += gl;
        if (body.length < p + 64 + 80 + 64 + 8) throw new Exception("профиль повреждён (короткий в 0012)");
        p += 64;                                   // публичный ключ админа (пин модели доверия)
        if ((body[p] & 0xff) != 1 || (body[p + 1] & 0xff) != 2) throw new Exception("это не клиентская грамота");
        p += 80 + 64;                              // грамота + её подпись админа
        long tv = le64(body, p);
        p += 8;
        if (body.length < p + 9) throw new Exception("профиль повреждён (нет таблицы)");
        long tv2 = le64(body, p);                  // ver внутри подписанного payload; обязаны совпасть
        p += 8;
        if (tv2 != tv) throw new Exception("профиль повреждён (версия таблицы)");
        int n = body[p++] & 0xff;
        String first = "";
        for (int i = 0; i < n; i++) {
            int nl = body[p++] & 0xff;
            String name = new String(body, p, nl, "UTF-8");
            if (i == 0) first = name;
            p += nl + 16 + 32;
            int m = body[p++] & 0xff;
            for (int k = 0; k < m; k++) {
                int t = body[p++] & 0xff;
                if (t == 3) p += 1 + (body[p] & 0xff);          // имя:порт текстом
                else p += (t == 4 ? 4 : 16) + 2;
            }
        }
        if (body.length - p < 64) throw new Exception("профиль повреждён (нет подписи таблицы)");
        p += 64;                                   // подпись таблицы
        if (p != body.length) throw new Exception("профиль повреждён (длина)");
        return new Profile(s, group, ip, n, first, true, tv);
    }
}
