package com.knothop.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/**
 * Настройки маршрутизации (файл state/routing.json, его читает нативная часть и перечитывает при изменении).
 *
 * <p>Режимы: "auto" - весь трафик через выход по умолчанию (его выбирает главный экран или телефон по RTT), "rules" - правила по спискам
 * geoip/geosite и свои записи. Рейтинга выходов и режима "priority" больше нет: при чтении старый "priority" считается "auto", а при
 * сохранении поле "priority" всегда пустое (старые клиенты и нативная часть не должны находить там скрытый порядок выходов).
 *
 * <p>Порядок проверки (значим): сначала свои записи (manual) сверху вниз, затем правила по спискам (rules) сверху вниз; побеждает первое
 * подходящее. Это порядок совпадений правил, а не приоритет выходов. Подсети с действием "direct" исполняются раньше любых правил: их
 * исключает из туннеля система при подключении.
 *
 * <p>Действия: "default" (выход по умолчанию), "direct" (мимо VPN, только для подсетей), "exit:&lt;hex32&gt;" (через указанный выход).
 *
 * <p>Выключенные правила нативная часть не видит: они лежат в "off_rules"/"off_manual" вместе с позицией "i" в общем списке и
 * возвращаются на место при включении. Остальные неизвестные поля файла (в том числе "ui_legacy") сохраняются как есть.
 */
final class RoutingCfg {
    static final int MAX_RULES = 64, MAX_MANUAL = 2000;
    static final String MODE_ALL = "auto", MODE_RULES = "rules";
    /** Нативная часть игнорирует файл крупнее 512 КиБ и работает без правил: не пишем больше этого предела с запасом. */
    private static final int MAX_FILE_BYTES = 480 * 1024;
    private static final int MAX_LEGACY_BACKUPS = 5;

    static final class Rule {
        String type, name, action;
        boolean enabled = true;
        Rule(String t, String n, String a) { type = t; name = n; action = a; }

        boolean geoip() { return "geoip".equals(type); }

        /** Нативная часть применяет только правила известного вида с понятным действием; остальные молча отбрасывает. */
        boolean valid() {
            return ("geoip".equals(type) || "geosite".equals(type)) && name != null && !name.isEmpty() && name.length() <= 80 && validAction(action);
        }

        /** «Мимо VPN» работает только для подсетей; для сайтов нативная часть отправляет трафик через выход по умолчанию. */
        boolean directUnsupported() { return "direct".equals(action) && !geoip(); }
    }

    static final class Manual {
        String value, action;
        boolean enabled = true;
        Manual(String v, String a) { value = v; action = a; }

        boolean ip() { return isIp(value); }

        boolean valid() { return value != null && !value.trim().isEmpty() && value.length() <= 253 && validAction(action); }

        boolean directUnsupported() { return "direct".equals(action) && !ip(); }
    }

    static final class Node {
        final String d, n;
        Node(String d, String n) { this.d = d; this.n = n; }
    }

    String mode = MODE_ALL;
    final List<Rule> rules = new ArrayList<>();
    final List<Manual> manual = new ArrayList<>();
    /** Файл существует, но не разобран: нативная часть его тоже игнорирует; первое сохранение заменит его. */
    boolean corrupt;
    /** При чтении найден старый рейтинг выходов или режим "priority" (см. migrateLegacy). */
    boolean hadLegacy;
    /** Поля файла, которыми модель не управляет: сохраняются без изменений. */
    private JSONObject rest = new JSONObject();
    private JSONArray legacyPriority = new JSONArray();
    private String legacyMode = "";

    static File file(File state) { return new File(state, "routing.json"); }

    /** Начальные настройки только для ещё не настроенного телефона. Никогда не заменяем существующий (даже повреждённый) файл пользователя. */
    static synchronized boolean ensureDefaults(File state) {
        if (file(state).exists()) return false;
        RoutingCfg c = new RoutingCfg();
        c.mode = MODE_RULES;
        for (String cidr : new String[]{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}) c.manual.add(new Manual(cidr, "direct"));
        c.rules.add(new Rule("geoip", "private", "direct"));
        c.rules.add(new Rule("geosite", "private", "direct"));
        c.rules.add(new Rule("geosite", "category-ru", "direct"));
        c.rules.add(new Rule("geoip", "ru", "direct"));
        return c.save(state).isEmpty();
    }

    // ---------------------------------------------------------------- чтение

    static RoutingCfg load(File state) {
        return parse(Util.read(file(state)));
    }

    static RoutingCfg parse(String text) {
        RoutingCfg c = new RoutingCfg();
        if (text == null || text.trim().isEmpty()) return c;
        try {
            JSONObject j = new JSONObject(text);
            String m = j.optString("mode", MODE_ALL);
            c.mode = m.equals(MODE_RULES) ? MODE_RULES : MODE_ALL;
            JSONArray p = j.optJSONArray("priority");
            for (int i = 0; p != null && i < p.length(); i++) if (p.optString(i).matches("[0-9a-f]{32}")) c.legacyPriority.put(p.optString(i));
            if (m.equals("priority") || c.legacyPriority.length() > 0) {
                c.hadLegacy = true;
                c.legacyMode = m;
            }
            JSONArray r = j.optJSONArray("rules");
            for (int i = 0; r != null && i < r.length() && c.rules.size() < MAX_RULES; i++) {
                JSONObject o = r.optJSONObject(i);
                if (o != null) c.rules.add(new Rule(o.optString("t"), o.optString("n"), o.optString("a")));
            }
            JSONArray mm = j.optJSONArray("manual");
            for (int i = 0; mm != null && i < mm.length() && c.manual.size() < MAX_MANUAL; i++) {
                JSONObject o = mm.optJSONObject(i);
                if (o != null) c.manual.add(new Manual(o.optString("v"), o.optString("a")));
            }
            insertOff(c.rules, j.optJSONArray("off_rules"), MAX_RULES, true);
            insertOff(c.manual, j.optJSONArray("off_manual"), MAX_MANUAL, false);
            Iterator<String> keys = j.keys();
            while (keys.hasNext()) {
                String k = keys.next();
                if (!isManaged(k)) c.rest.put(k, j.get(k));
            }
        } catch (Throwable t) {
            RoutingCfg bad = new RoutingCfg();
            bad.corrupt = true;
            return bad;
        }
        return c;
    }

    private static boolean isManaged(String k) {
        return k.equals("mode") || k.equals("priority") || k.equals("rules") || k.equals("manual") || k.equals("off_rules") || k.equals("off_manual");
    }

    /** Возвращает выключенные записи на их места в общем списке (по возрастанию позиции, поэтому индексы остаются верными). */
    @SuppressWarnings("unchecked")
    private static <T> void insertOff(List<T> list, JSONArray off, int max, boolean rule) {
        if (off == null) return;
        List<Object[]> items = new ArrayList<>();
        for (int i = 0; i < off.length(); i++) {
            JSONObject o = off.optJSONObject(i);
            if (o == null) continue;
            Object e;
            if (rule) {
                Rule x = new Rule(o.optString("t"), o.optString("n"), o.optString("a"));
                x.enabled = false;
                e = x;
            } else {
                Manual x = new Manual(o.optString("v"), o.optString("a"));
                x.enabled = false;
                e = x;
            }
            items.add(new Object[]{Math.max(0, o.optInt("i", Integer.MAX_VALUE)), e});
        }
        java.util.Collections.sort(items, (a, b) -> Integer.compare((Integer) a[0], (Integer) b[0]));
        for (Object[] it : items) {
            if (list.size() >= max) break;
            list.add(Math.min((Integer) it[0], list.size()), (T) it[1]);
        }
    }

    // ---------------------------------------------------------------- запись

    /** Сохраняет настройки атомарно; возвращает пустую строку или причину отказа. Нативная часть подхватывает файл за секунду. */
    String save(File state) {
        try {
            String s = toJson().toString();
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            if (b.length > MAX_FILE_BYTES) return "слишком много записей: файл настроек не должен превышать " + (MAX_FILE_BYTES >> 10) + " КиБ";
            state.mkdirs();
            File tmp = new File(state, "routing.json.tmp");
            Files.write(tmp.toPath(), b);
            Files.move(tmp.toPath(), file(state).toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            corrupt = false;
            hadLegacy = false;
            return "";
        } catch (Throwable t) {
            return "не удалось сохранить: " + t.getClass().getSimpleName();
        }
    }

    JSONObject toJson() throws Exception {
        JSONObject j = new JSONObject();
        Iterator<String> keys = rest.keys();
        while (keys.hasNext()) {
            String k = keys.next();
            j.put(k, rest.get(k));
        }
        j.put("mode", mode);
        // рейтинга выходов нет: пустое поле нужно, чтобы ни один читатель не нашёл в файле скрытый порядок
        j.put("priority", new JSONArray());
        JSONArray r = new JSONArray(), roff = new JSONArray();
        for (int i = 0; i < rules.size(); i++) {
            Rule x = rules.get(i);
            JSONObject o = new JSONObject().put("t", x.type).put("n", x.name).put("a", x.action);
            if (x.enabled) r.put(o);
            else roff.put(o.put("i", i));
        }
        j.put("rules", r);
        if (roff.length() > 0) j.put("off_rules", roff);
        JSONArray m = new JSONArray(), moff = new JSONArray();
        for (int i = 0; i < manual.size(); i++) {
            Manual x = manual.get(i);
            JSONObject o = new JSONObject().put("v", x.value).put("a", x.action);
            if (x.enabled) m.put(o);
            else moff.put(o.put("i", i));
        }
        j.put("manual", m);
        if (moff.length() > 0) j.put("off_manual", moff);
        return j;
    }

    // ---------------------------------------------------------------- миграция старого рейтинга выходов

    /**
     * Одноразовая явная миграция: если файл содержит рейтинг выходов (или режим "priority"), прежние значения записываются в блок
     * "ui_legacy" этого же файла (с флагом ack=false, пока пользователь не увидел сообщение), "priority" очищается, "priority" -> "auto".
     * Правила и свои записи не меняются. Возвращает true, если файл переписан. Значения в журнал не пишутся.
     */
    static boolean migrateLegacy(File state) {
        if (!file(state).isFile()) return false;
        RoutingCfg c = load(state);
        if (c.corrupt || !c.hadLegacy) return false;
        if (c.legacyPriority.length() > 0) {
            try {
                JSONArray all = c.rest.optJSONArray("ui_legacy");
                JSONArray keep = new JSONArray();
                int from = all == null ? 0 : Math.max(0, all.length() - (MAX_LEGACY_BACKUPS - 1));
                for (int i = from; all != null && i < all.length(); i++) keep.put(all.get(i));
                keep.put(new JSONObject().put("at", System.currentTimeMillis()).put("mode", c.legacyMode).put("priority", c.legacyPriority).put("ack", false));
                c.rest.put("ui_legacy", keep);
            } catch (Throwable t) {
                return false;
            }
        }
        return c.save(state).isEmpty();
    }

    /** Последняя резервная копия старых приоритетов, о которой пользователь ещё не уведомлён; иначе null. */
    JSONObject unackedLegacy() {
        JSONArray a = rest.optJSONArray("ui_legacy");
        JSONObject last = a == null || a.length() == 0 ? null : a.optJSONObject(a.length() - 1);
        return last != null && !last.optBoolean("ack", true) ? last : null;
    }

    int legacyCount(JSONObject backup) {
        JSONArray p = backup == null ? null : backup.optJSONArray("priority");
        return p == null ? 0 : p.length();
    }

    /** Поля файла вне модели (для проверок). */
    JSONObject rest() { return rest; }

    void ackLegacy() {
        JSONArray a = rest.optJSONArray("ui_legacy");
        for (int i = 0; a != null && i < a.length(); i++) {
            JSONObject o = a.optJSONObject(i);
            if (o != null) try { o.put("ack", true); } catch (Throwable ignored) { }
        }
    }

    // ---------------------------------------------------------------- вычисления

    /** Подпись частей, которые действуют только при создании туннеля (правила «мимо VPN»): изменились - нужно переподключиться. */
    String directSig() {
        if (!mode.equals(MODE_RULES)) return "";
        StringBuilder s = new StringBuilder();
        for (Rule r : rules) if (r.enabled && r.action.equals("direct")) s.append(r.type).append(':').append(r.name).append(';');
        for (Manual m : manual) if (m.enabled && m.action.equals("direct")) s.append(m.value).append(';');
        return s.toString();
    }

    int enabledRules() {
        int n = 0;
        for (Rule r : rules) if (r.enabled) n++;
        for (Manual m : manual) if (m.enabled) n++;
        return n;
    }

    /** Есть ли включённые правила по сайтам (geosite или домены): для них нативная часть читает DNS-ответы и блокирует DNS по TLS. */
    boolean hasDomainRules() {
        for (Rule r : rules) if (r.enabled && !r.geoip()) return true;
        for (Manual m : manual) if (m.enabled && !m.ip()) return true;
        return false;
    }

    static boolean validAction(String a) {
        return "default".equals(a) || "direct".equals(a) || (a != null && a.matches("exit:[0-9a-fA-F]{32}"));
    }

    static boolean isIp(String v) {
        if (v == null || !v.matches("\\d{1,3}(\\.\\d{1,3}){3}(/\\d{1,2})?")) return false;
        String[] pr = v.split("/");
        for (String o : pr[0].split("\\.")) if (Integer.parseInt(o) > 255) return false;
        return pr.length == 1 || Integer.parseInt(pr[1]) <= 32;
    }

    /**
     * Проверка и приведение строки своей записи тем же способом, что в нативной части: IPv4/CIDR либо домен с необязательным
     * префиксом full:/domain:/keyword:. Возвращает запись как введена (без пробелов по краям) или null, если разобрать нельзя.
     */
    static String cleanManual(String line) {
        String s = line == null ? "" : line.trim();
        if (s.isEmpty() || s.length() > 253) return null;
        if (isIp(s)) return s;
        String v = s.toLowerCase(Locale.ROOT), val = v;
        int c = v.indexOf(':');
        if (c >= 0) {
            String pre = v.substring(0, c);
            if (!pre.equals("full") && !pre.equals("domain") && !pre.equals("keyword")) return null;
            val = v.substring(c + 1);
        }
        val = val.trim();
        while (val.startsWith("*.")) val = val.substring(2);
        while (val.startsWith(".")) val = val.substring(1);
        while (val.endsWith(".")) val = val.substring(0, val.length() - 1);
        if (val.isEmpty()) return null;
        for (int i = 0; i < val.length(); i++) {
            char ch = val.charAt(i);
            if (!(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '.' && ch != '-' && ch != '_' && ch < 0x80) return null;
        }
        return s;
    }

    // ---------------------------------------------------------------- известные выходы

    /** Выходы, известные приложению: из живого status.json, иначе из сохранённого списка. */
    static List<Node> nodes(File filesDir) {
        List<Node> out = new ArrayList<>();
        try {
            JSONArray a = new JSONArray(Util.read(new File(filesDir, "routing_nodes.json")));
            for (int i = 0; i < a.length(); i++) out.add(new Node(a.getJSONObject(i).getString("d"), a.getJSONObject(i).optString("n")));
        } catch (Throwable ignored) { }
        return out;
    }

    static void cacheNodes(File filesDir, JSONArray exits) {
        try {
            // объединяем с прежним кэшем: узел, пропавший из списка на время, остаётся доступным для настройки; имя-хеш не затирает нормальное
            java.util.LinkedHashMap<String, String> m = new java.util.LinkedHashMap<>();
            for (Node n : nodes(filesDir)) m.put(n.d, n.n);
            boolean any = false;
            for (int i = 0; exits != null && i < exits.length(); i++) {
                JSONObject e = exits.optJSONObject(i);
                if (e == null || !e.optString("d").matches("[0-9a-f]{32}")) continue;
                String d = e.optString("d"), n = e.optString("n");
                String old = m.get(d);
                boolean hexName = n.isEmpty() || n.matches("[0-9a-f]{6,32}");
                if (old == null || !hexName) m.put(d, n);
                any = true;
            }
            if (!any) return;
            JSONArray a = new JSONArray();
            for (java.util.Map.Entry<String, String> e : m.entrySet()) {
                if (a.length() >= 32) break;
                a.put(new JSONObject().put("d", e.getKey()).put("n", e.getValue()));
            }
            String s = a.toString();
            File f = new File(filesDir, "routing_nodes.json");
            if (s.equals(Util.read(f))) return;
            Files.write(f.toPath(), s.getBytes(StandardCharsets.UTF_8));
        } catch (Throwable ignored) { }
    }
}
