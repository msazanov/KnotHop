package com.knothop.vpn;

import java.util.Iterator;

/**
 * Режимы-пресеты маршрутизации как данные. Пресет описывает: режим клиента (auto/rules), раздельное туннелирование (исключать «мимо VPN»
 * или включать только выбранное), и набор записей: свои адреса (manual) и списки geoip/geosite. Применение ({@link #apply}) убирает записи,
 * порождённые любым пресетом, оставляя записи пользователя («свои правила») на прежнем месте впереди, и дописывает записи выбранного пресета.
 * Свои правила проверяются раньше пресетных, поэтому ими можно переопределить пресет.
 *
 * <p>Как пресеты исполняются:
 * <ul>
 * <li>{@link #ALL_TUNNEL}: mode auto, весь трафик через выход (при своих правилах - mode rules без пресетных записей).</li>
 * <li>{@link #ALL_DIRECT}: TUN поднимается без маршрутов (служба), трафик идёт мимо VPN. Интерфейс показывает красное предупреждение.</li>
 * <li>{@link #BLOCKED}: split=include. В туннель попадают только подсети geoip RU-BLOCKED (и подсети своих правил с выходом); DNS через туннель;
 *     локальные сети напрямую. Нативная часть пишет tunnel.cidr по тем же спискам, что и direct.cidr. Сайты из geosite RU-BLOCKED узнаются по DNS,
 *     но адрес, которого нет в подсетях, в туннель не попадёт (ограничение VpnService).</li>
 * <li>{@link #RU_DIRECT}: исключаются из туннеля geoip RU и локальные сети (direct.cidr), остальное в туннель. Домены российских сайтов
 *     (geosite category-ru) сохраняются как правила, но «мимо VPN» для доменов не исполняется нативной частью.</li>
 * </ul>
 * Торренты «напрямую» нативная часть не умеет (нет сопоставления по протоколу); ограничение показывается в пояснении пресета.
 */
final class RoutingPresets {
    private RoutingPresets() { }

    static final String ALL_TUNNEL = "tunnel", ALL_DIRECT = "direct", BLOCKED = "blocked", RU_DIRECT = "ru";
    static final String DEFAULT = BLOCKED;
    /** Слова по умолчанию для фильтра выходов: исключить российскую ноду. */
    static final String[] DEFAULT_EXCLUDE = {"россия", "russia"};
    static final String[] PRIVATE_CIDRS = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"};

    static final class Preset {
        final String id, title, help;
        final boolean unsafe;
        /** type, name, action для списков; для manual: "m", значение, действие. */
        final String[][] entries;
        Preset(String id, String title, String help, boolean unsafe, String[][] entries) {
            this.id = id; this.title = title; this.help = help; this.unsafe = unsafe; this.entries = entries;
        }
    }

    private static String[][] privateEntries() {
        String[][] e = new String[PRIVATE_CIDRS.length][];
        for (int i = 0; i < e.length; i++) e[i] = new String[]{"m", PRIVATE_CIDRS[i], "direct"};
        return e;
    }

    private static String[][] concat(String[][] a, String[][] b) {
        String[][] r = new String[a.length + b.length][];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static final Preset[] ALL = {
        new Preset(BLOCKED, "Обход только заблокированного",
                "В туннель идёт только то, что заблокировано в России (списки geoip RU-BLOCKED из runetfreedom), и DNS. Всё остальное, включая локальные сети, идёт напрямую. "
                + "Торренты напрямую: приложение не распознаёт протокол, поэтому они идут напрямую, только если их адреса не входят в списки заблокированного. "
                + "Сайт, адрес которого не попал в списки подсетей, пойдёт напрямую. Нужны файлы списков (скачиваются из «Файлы списков» или потягиванием главного экрана). "
                + "Без них включается полный туннель.", false,
                concat(privateEntries(), new String[][]{{"geoip", "private", "direct"}, {"geosite", "private", "direct"}, {"geosite", "RU-BLOCKED", "default"}, {"geoip", "RU-BLOCKED", "default"}})),
        new Preset(RU_DIRECT, "Всё РФ напрямую",
                "Адреса России (geoip RU) и локальные сети идут напрямую, остальное — через выход. Российские сайты по доменам (category-ru) сохраняются в правилах, "
                + "но напрямую отправляются только по IP-подсетям. Нужны файлы списков.", false,
                concat(privateEntries(), new String[][]{{"geoip", "private", "direct"}, {"geosite", "private", "direct"}, {"geosite", "category-ru", "direct"}, {"geoip", "ru", "direct"}})),
        new Preset(ALL_TUNNEL, "Всё в туннель",
                "Весь трафик идёт через выход, без исключений. Свои правила (если есть) продолжают работать.", false, new String[0][]),
        new Preset(ALL_DIRECT, "Всё напрямую ⚠",
                "VPN поднимается без маршрутов: весь трафик идёт напрямую, мимо туннеля и выходов. Трафик НЕ защищён, сайты и провайдер видят ваш настоящий адрес. "
                + "Режим нужен, чтобы оставаться в сети нод и временно не гнать трафик через выход.", true, new String[0][]),
    };

    static Preset find(String id) {
        for (Preset p : ALL) if (p.id.equals(id)) return p;
        return null;
    }

    static String title(RoutingCfg c) {
        Preset p = find(c.preset());
        return p == null ? "Свои правила" : p.title;
    }

    static boolean isPresetRule(RoutingCfg.Rule r) {
        for (Preset p : ALL) for (String[] e : p.entries)
            if (!e[0].equals("m") && e[0].equals(r.type) && e[1].equalsIgnoreCase(r.name) && e[2].equals(r.action)) return true;
        return false;
    }

    static boolean isPresetManual(RoutingCfg.Manual m) {
        for (Preset p : ALL) for (String[] e : p.entries)
            if (e[0].equals("m") && e[1].equalsIgnoreCase(m.value) && e[2].equals(m.action)) return true;
        return false;
    }

    /** Свои (не пресетные) записи: правила и адреса, включая выключенные. */
    static int customCount(RoutingCfg c) {
        int n = 0;
        for (RoutingCfg.Rule r : c.rules) if (!isPresetRule(r)) n++;
        for (RoutingCfg.Manual m : c.manual) if (!isPresetManual(m)) n++;
        return n;
    }

    /** Записи пресета не должны выпадать из-за предела: свои правила остаются, лишние пресетные не добавляются. */
    static void apply(RoutingCfg c, String id) {
        Preset p = find(id);
        if (p == null) return;
        for (Iterator<RoutingCfg.Rule> it = c.rules.iterator(); it.hasNext();) if (isPresetRule(it.next())) it.remove();
        for (Iterator<RoutingCfg.Manual> it = c.manual.iterator(); it.hasNext();) if (isPresetManual(it.next())) it.remove();
        for (String[] e : p.entries) {
            if (e[0].equals("m")) { if (c.manual.size() < RoutingCfg.MAX_MANUAL) c.manual.add(new RoutingCfg.Manual(e[1], e[2])); }
            else if (c.rules.size() < RoutingCfg.MAX_RULES) c.rules.add(new RoutingCfg.Rule(e[0], e[1], e[2]));
        }
        c.setPreset(id);
        c.setSplitInclude(id.equals(BLOCKED));
        boolean custom = customCount(c) > 0;
        // «Всё напрямую» и «Всё в туннель» без своих правил обходятся режимом auto; пресеты со списками и свои правила требуют mode rules
        c.mode = (id.equals(ALL_DIRECT) || (id.equals(ALL_TUNNEL) && !custom)) ? RoutingCfg.MODE_ALL : RoutingCfg.MODE_RULES;
    }
}
