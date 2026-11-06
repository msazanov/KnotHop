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

    /** Пресеты приглашения: только заполняют права; логика выпуска одна для всех (стопка пар по выбранным нодам). */
    static final int P_SERVER = 0, P_USER = 1, P_ADMIN = 2, P_CUSTOM = 3;
    static final String[] PRESET_NAMES = {"Сервер", "Пользователь", "Админ", "Свои"};
    static final String[] PRESET_HINTS = {
        "новая нода: пользуется выбранными нодами (USE), а этот телефон получает над ней управление (CONFIG, ADD, REMOVE, USE)",
        "телефон или ПК: пользуется выбранными нодами (USE); выход в интернет — свойство самой ноды",
        "второй админ: CONFIG, ADD, REMOVE и USE на выбранных нодах",
        "права выставлены вручную"};

    private Rights() { }

    /** Права получателя на выбранных нодах для пресета ({@link #P_CUSTOM}: 0 - значение остаётся ручным). */
    static int presetRights(int preset) {
        switch (preset) {
            case P_SERVER: return SERVER;
            case P_USER: return USER;
            case P_ADMIN: return ADMIN;
            default: return 0;
        }
    }

    /** Управление получателем для выдавшего (этот телефон): только у «Сервера». */
    static int presetMgmt(int preset) { return preset == P_SERVER ? ADMIN : 0; }

    /** Пресет, которому соответствуют права; иначе «Свои». */
    static int presetFor(int rights, int mgmt) {
        for (int p = P_SERVER; p <= P_ADMIN; p++) if (presetRights(p) == rights && presetMgmt(p) == mgmt) return p;
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
