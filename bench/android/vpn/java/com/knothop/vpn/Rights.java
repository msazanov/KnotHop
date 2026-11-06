package com.knothop.vpn;

/** Биты прав таблицы ноды (ADR 0028 §1.5) и их показ. TRANSIT и EXIT - права самой ноды (локальные `transit_enabled`/`exit_enabled`). */
final class Rights {
    static final int USE = 1, TRANSIT = 2, EXIT = 4, ADD = 8, REMOVE = 16, CONFIG = 32, HOST_ACCESS = 64;
    static final int[] BITS = {USE, ADD, REMOVE, CONFIG, HOST_ACCESS};
    static final String[] NAMES = {"USE", "ADD", "REMOVE", "CONFIG", "HOST_ACCESS"};
    static final String[] HINTS = {
        "подключаться к ноде и пользоваться ею (в т.ч. выходом, если нода выход)",
        "добавлять приглашения и записи не выше своих прав",
        "понижать и убирать записи не выше своих прав",
        "админ ноды: любые правки, настройки, статус",
        "доступ к службам самого сервера (только выдаёт админ)"};
    static final int USER = USE, SERVER = USE, ADMIN = CONFIG | ADD | REMOVE | USE;

    private Rights() { }

    static String text(int mask) {
        StringBuilder b = new StringBuilder();
        String[] all = {"USE", "TRANSIT", "EXIT", "ADD", "REMOVE", "CONFIG", "HOST_ACCESS"};
        for (int i = 0; i < all.length; i++) if ((mask & (1 << i)) != 0) b.append(b.length() == 0 ? "" : ", ").append(all[i]);
        return b.length() == 0 ? "нет" : b.toString();
    }

    static String clip(String s) {
        String v = s == null ? "" : s.replaceAll("[\\p{Cntrl}]", " ");
        return v.length() > 120 ? v.substring(0, 120) + "…" : v;
    }

    static String roles(int mask) {
        StringBuilder b = new StringBuilder();
        if ((mask & EXIT) != 0) b.append("выход");
        if ((mask & TRANSIT) != 0) b.append(b.length() == 0 ? "" : " · ").append("транзит/PN");
        return b.length() == 0 ? "клиент" : b.toString();
    }
}
