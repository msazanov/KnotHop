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

    /**
     * Пресеты приглашения: только заполняют права получателя НА ВЫПУСТИВШЕЙ НОДЕ (ADR 0028 §1.4); второго набора («управление получателем») нет.
     * «Сервер» по правам совпадает с «Пользователем» (USE): отличие в подсказке - сервер при первом запуске по этой строке сам признаёт
     * выдавшего админом (это свойство запуска сервера с --invite-file, а не прав в приглашении).
     */
    static final int P_USER = 0, P_SERVER = 1, P_ADMIN = 2, P_CUSTOM = 3;
    static final String[] PRESET_NAMES = {"Пользователь", "Сервер", "Админ", "Свои"};
    static final String[] PRESET_HINTS = {
        "телефон или ПК: пользуется выбранными нодами (USE); выход в интернет — свойство самой ноды",
        "новая нода: пользуется выбранными нодами (USE). Сервер по этой строке при первом запуске признает вас админом",
        "второй админ: CONFIG, ADD, REMOVE и USE на выбранных нодах",
        "права выставлены вручную"};

    private Rights() { }

    /** Права получателя на выпустившей ноде для пресета ({@link #P_CUSTOM}: 0 - значение остаётся ручным). */
    static int presetRights(int preset) {
        switch (preset) {
            case P_USER: return USER;
            case P_SERVER: return SERVER;
            case P_ADMIN: return ADMIN;
            default: return 0;
        }
    }

    /** Пресет, которому соответствуют права; иначе «Свои». При равных правах («Пользователь» и «Сервер») берётся «Пользователь». */
    static int presetFor(int rights) {
        for (int p = P_USER; p <= P_ADMIN; p++) if (presetRights(p) == rights) return p;
        return P_CUSTOM;
    }

    /** Что из запрошенного выходит за мои права на чужой ноде (0 - всё в пределах; держатель CONFIG ограничений не имеет). */
    static int exceeds(int want, int mine) {
        return (mine & CONFIG) != 0 ? 0 : (want & ~mine);
    }

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
