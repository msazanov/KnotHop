package com.knothop.vpn;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** JVM-проверка разбора приглашения v4 (ADR 0019); формат совпадает с enroll::Invite. В APK не входит. */
public final class ProfileCheck {
    static String enc(byte[][] nodes, byte[] pin) throws Exception {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        for (byte[] n : nodes) o.write(n);
        o.write(pin);
        byte[] body = o.toByteArray();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("knothop-invite-v4".getBytes(StandardCharsets.US_ASCII));
        byte[] sum = md.digest(body);
        o.write(sum, 0, 4);
        return "kh-" + android.util.Base64.encodeToString(o.toByteArray(), 0);
    }

    static byte[] node(int v) {
        byte[] b = new byte[16];
        Arrays.fill(b, (byte) v);
        return b;
    }

    static byte[] pin(int v) {
        byte[] b = new byte[24];
        Arrays.fill(b, (byte) v);
        return b;
    }

    static void bad(String s, String why) {
        try {
            Profile.parse(s);
        } catch (Exception e) {
            return;
        }
        throw new AssertionError("должно быть отклонено: " + why);
    }

    static void check(boolean c, String what) {
        if (!c) throw new AssertionError(what);
    }

    public static void main(String[] a) throws Exception {
        String one = enc(new byte[][]{node(1)}, pin(7));
        check(one.length() - 3 == 59, "хвост из одной ноды 59 символов");
        Profile p = Profile.parse(one);
        check(p.nodeCount == 1 && !p.own(), "одна нода");
        check(Profile.parse(" " + one.substring(0, 20) + "\n" + one.substring(20) + " ").nodeCount == 1, "пробелы и переносы");
        check(Profile.parse(Profile.LINK + one.substring(3)).raw.equals(one), "ссылка из QR");

        byte[][] eight = new byte[8][];
        for (int i = 0; i < 8; i++) eight[i] = node(i + 1);
        String max = enc(eight, pin(9));
        check(max.length() - 3 == 208, "хвост из восьми нод 208 символов");
        check(Profile.parse(max).nodeCount == 8, "восемь нод");

        check(Profile.parse("").own() && Profile.parse("own").own(), "своя сеть");
        Profile en = Profile.parse("enrolled");
        check(en.enrolled && !en.own() && en.raw.isEmpty() && en.nodeCount == 0, "принятое приглашение: без pin, не своя сеть");
        check(!Profile.parse("").enrolled && !Profile.parse(one).enrolled, "enrolled только у маркера");

        bad(enc(new byte[][]{node(2), node(1)}, pin(7)), "порядок нод");
        bad(enc(new byte[][]{node(1), node(1)}, pin(7)), "повтор ноды");
        bad(enc(new byte[][]{node(1)}, pin(0)), "нулевой pin");
        byte[][] nine = new byte[9][];
        for (int i = 0; i < 9; i++) nine[i] = node(i + 1);
        bad(enc(nine, pin(9)), "девять нод");
        bad(one.substring(0, one.length() - 1) + (one.charAt(one.length() - 1) == 'A' ? 'B' : 'A'), "контрольная сумма");
        bad("kh3-" + one.substring(3), "старая версия kh3-");
        bad("kh-AA", "короткая строка");
        bad(one + "!", "лишние символы");
        bad(new String(new char[4097]).replace((char) 0, (char) 120), "длина");
        System.out.println("ProfileCheck OK");
    }
}
