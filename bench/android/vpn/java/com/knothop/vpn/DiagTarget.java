package com.knothop.vpn;

import java.util.ArrayList;
import java.util.List;

/**
 * Адрес диагностики («Пинг», «IP / регион»): всегда идёт в туннель при любых правилах маршрутизации (кроме «Всё напрямую», где туннеля нет).
 * Cloudflare 1.0.0.1: страница /cdn-cgi/trace отдаёт ip= и loc= без DNS, сертификат cloudflare-dns.com содержит IP SAN 1.0.0.1 (проверено).
 * Гарантия двойная: (1) в TUN добавляется маршрут /32 ({@link #INCLUDE_EXTRA}), (2) адрес вырезается из списка «мимо VPN» ({@link #carveOut}),
 * чтобы excludeRoute (Android 13+) не перекрыл его. Нативный роутер (route.rs, DIAG_IP) отправляет его на основной выход, а не мимо/на чужой выход.
 */
final class DiagTarget {
    private DiagTarget() { }

    static final String HOST = "1.0.0.1";
    static final String URL = "https://" + HOST + "/cdn-cgi/trace";
    /** Маршруты, которые всегда добавляются в режиме «только выбранное»: DNS-серверы туннеля и адрес диагностики. */
    static final String[] INCLUDE_EXTRA = {"1.1.1.1/32", "8.8.8.8/32", HOST + "/32"};

    static long parseIp(String s) {
        String[] p = s.split("\\.");
        if (p.length != 4) return -1;
        long v = 0;
        try {
            for (String x : p) {
                int n = Integer.parseInt(x);
                if (n < 0 || n > 255) return -1;
                v = (v << 8) | n;
            }
        } catch (NumberFormatException e) { return -1; }
        return v;
    }

    static String fmt(long ip) {
        return ((ip >> 24) & 255) + "." + ((ip >> 16) & 255) + "." + ((ip >> 8) & 255) + "." + (ip & 255);
    }

    private static long mask(int len) { return len == 0 ? 0 : (0xffffffffL << (32 - len)) & 0xffffffffL; }

    /** Подсеть a.b.c.d/n содержит адрес; ошибка разбора - false. */
    static boolean contains(String cidr, long ip) {
        int i = cidr.indexOf('/');
        if (i < 0) return false;
        long net = parseIp(cidr.substring(0, i));
        int len;
        try { len = Integer.parseInt(cidr.substring(i + 1)); } catch (NumberFormatException e) { return false; }
        if (net < 0 || len < 0 || len > 32) return false;
        return (ip & mask(len)) == (net & mask(len));
    }

    /** В include-режиме Builder добавляет не только выбранные подсети, но и служебные /32. */
    static boolean included(long ip, List<String> routes) {
        for (String c : routes) if (contains(c, ip)) return true;
        for (String c : INCLUDE_EXTRA) if (contains(c, ip)) return true;
        return false;
    }

    /** Список «мимо VPN» без адреса диагностики: накрывающая подсеть заменяется соседними блоками (не больше 32), остальные не меняются. */
    static List<String> carveOut(List<String> cidrs) { return carveOut(cidrs, parseIp(HOST)); }

    static List<String> carveOut(List<String> cidrs, long ip) {
        List<String> out = new ArrayList<>(cidrs.size() + 32);
        for (String c : cidrs) {
            if (!contains(c, ip)) { out.add(c); continue; }
            int len = Integer.parseInt(c.substring(c.indexOf('/') + 1));
            for (int l = len + 1; l <= 32; l++) {
                long sibling = (ip & mask(l)) ^ (1L << (32 - l));
                out.add(fmt(sibling) + "/" + l);
            }
        }
        return out;
    }

    /**
     * Модель итоговой таблицы маршрутов TUN: уходит ли адрес диагностики в туннель.
     * @param include null - полный туннель (0.0.0.0/0); иначе подсети режима «только выбранное» (к ним служба всегда добавляет INCLUDE_EXTRA)
     * @param excluded подсети «мимо VPN», уже прошедшие carveOut (как в службе)
     */
    static boolean routedToTunnel(boolean allDirect, List<String> include, List<String> excluded) {
        if (allDirect) return false;
        long ip = parseIp(HOST);
        if (include == null) {
            for (String c : excluded) if (contains(c, ip)) return false;
            return true;
        }
        return included(ip, include);
    }

    /** Разбор ответа /cdn-cgi/trace (строки key=value): [0] - ip, [1] - loc (код страны), пустые строки, если полей нет. */
    static String[] parseTrace(String body) {
        String ip = "", loc = "";
        for (String l : body.split("\n")) {
            if (l.startsWith("ip=")) ip = l.substring(3).trim();
            else if (l.startsWith("loc=")) loc = l.substring(4).trim();
        }
        return new String[]{ip, loc};
    }

    static String country(String cc) {
        if (cc.length() != 2) return cc;
        return new java.util.Locale("", cc).getDisplayCountry(new java.util.Locale("ru")) + " (" + cc + ")";
    }
}
