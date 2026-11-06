package com.knothop.vpn;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** JVM-проверка разбора приглашения v4 (ADR 0019); формат совпадает с enroll::Invite. В APK не входит. */
public final class ProfileCheck {
    static String enc(byte[][] nodes, byte[][] pins) throws Exception {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(1);
        o.write(nodes.length);
        for (int i = 0; i < nodes.length; i++) { o.write(nodes[i]); o.write(pins[i]); }
        byte[] body = o.toByteArray();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("knothop-invite-v5".getBytes(StandardCharsets.US_ASCII));
        byte[] sum = md.digest(body);
        o.write(sum, 0, 4);
        return android.util.Base64.encodeToString(o.toByteArray(), android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING | android.util.Base64.NO_WRAP);
    }

    static byte[][] pins(int n, int v) {
        byte[][] p = new byte[n][];
        for (int i = 0; i < n; i++) p[i] = pin(v);
        return p;
    }

    static byte[] node(int v) {
        byte[] b = new byte[16];
        Arrays.fill(b, (byte) v);
        return b;
    }

    static byte[] pin(int v) {
        byte[] b = new byte[16];
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
        String one = enc(new byte[][]{node(1)}, pins(1, 7));
        check(one.length() == 51, "одна нода 51 знак");
        Profile p = Profile.parse(one);
        check(p.nodeCount == 1 && !p.own() && p.nodeHash(0).equals("01".repeat(16)), "одна нода и её хеш");
        check(Profile.parse(" " + one.substring(0, 20) + "\n" + one.substring(20) + " ").nodeCount == 1, "пробелы и переносы");
        check(Profile.parse(Profile.LINK + one).raw.equals(one), "ссылка из QR");

        byte[][] eight = new byte[8][];
        for (int i = 0; i < 8; i++) eight[i] = node(i + 1);
        String max = enc(eight, pins(8, 9));
        check(max.length() == 350, "восемь нод 350 знаков");
        check(Profile.parse(max).nodeCount == 8, "восемь нод");

        check(Profile.parse("").own() && Profile.parse("own").own(), "своя сеть");
        Profile en = Profile.parse("enrolled");
        check(en.enrolled && !en.own() && en.raw.isEmpty() && en.nodeCount == 0, "погашенное приглашение: без pin, не своя сеть");
        check(!Profile.parse("").enrolled && !Profile.parse(one).enrolled, "enrolled только у маркера");

        bad(enc(new byte[][]{node(2), node(1)}, pins(2, 7)), "порядок нод");
        bad(enc(new byte[][]{node(1), node(1)}, pins(2, 7)), "повтор ноды");
        bad(enc(new byte[][]{node(1)}, pins(1, 0)), "нулевой pin");
        byte[][] nine = new byte[9][];
        for (int i = 0; i < 9; i++) nine[i] = node(i + 1);
        bad(enc(nine, pins(9, 9)), "девять нод");
        bad(one.substring(0, one.length() - 1) + (one.charAt(one.length() - 1) == 'A' ? 'B' : 'A'), "контрольная сумма");
        bad("kh-" + one, "старый формат kh-");
        bad("khs-" + one, "старый формат khs-");
        bad("AA", "короткая строка");
        bad(one + "!", "лишние символы");
        bad(new String(new char[4097]).replace((char) 0, (char) 120), "длина");
        System.out.println("ProfileCheck OK");
    }
}
