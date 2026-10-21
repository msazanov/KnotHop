package com.rawg.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/**
 * Настройки маршрутизации (файл state/routing.json, его читает нативная часть и перечитывает при изменении).
 * Режимы: auto (выход выбирается по RTT телефона), priority (выходы по списку приоритетов), rules (приоритеты + правила по спискам
 * geoip/geosite и ручные записи). Побеждает первое подходящее: сначала ручные записи, затем правила в порядке списка.
 * Действия: "default" (основной выход), "direct" (мимо VPN, только для подсетей), "exit:&lt;hex32&gt;" (через указанный выход).
 */
final class RoutingCfg {
    static final int MAX_RULES = 64, MAX_MANUAL = 2000;

    static final class Rule {
        String type, name, action;
        Rule(String t, String n, String a) { type = t; name = n; action = a; }
    }

    static final class Manual {
        String value, action;
        Manual(String v, String a) { value = v; action = a; }
    }

    static final class Node {
        final String d, n;
        Node(String d, String n) { this.d = d; this.n = n; }
    }

    String mode = "auto";
    final List<String> priority = new ArrayList<>();
    final List<Rule> rules = new ArrayList<>();
    final List<Manual> manual = new ArrayList<>();

    static File file(File state) { return new File(state, "routing.json"); }

    static RoutingCfg load(File state) {
        RoutingCfg c = new RoutingCfg();
        try {
            JSONObject j = new JSONObject(Util.read(file(state)));
            String m = j.optString("mode", "auto");
            c.mode = m.equals("priority") || m.equals("rules") ? m : "auto";
            JSONArray p = j.optJSONArray("priority");
            for (int i = 0; p != null && i < p.length(); i++) if (p.optString(i).matches("[0-9a-f]{32}")) c.priority.add(p.optString(i));
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
        } catch (Throwable ignored) { }
        return c;
    }

    void save(File state) {
        try {
            JSONObject j = new JSONObject();
            j.put("mode", mode);
            j.put("priority", new JSONArray(priority));
            JSONArray r = new JSONArray();
            for (Rule x : rules) r.put(new JSONObject().put("t", x.type).put("n", x.name).put("a", x.action));
            j.put("rules", r);
            JSONArray m = new JSONArray();
            for (Manual x : manual) m.put(new JSONObject().put("v", x.value).put("a", x.action));
            j.put("manual", m);
            state.mkdirs();
            File tmp = new File(state, "routing.json.tmp");
            Files.write(tmp.toPath(), j.toString().getBytes(StandardCharsets.UTF_8));
            Files.move(tmp.toPath(), file(state).toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Throwable ignored) { }
    }

    /** Подпись частей, которые действуют только при создании туннеля (правила «мимо VPN»): изменились - нужно переподключиться. */
    String directSig() {
        if (!mode.equals("rules")) return "";
        StringBuilder s = new StringBuilder();
        for (Rule r : rules) if (r.action.equals("direct")) s.append(r.type).append(':').append(r.name).append(';');
        for (Manual m : manual) if (m.action.equals("direct")) s.append(m.value).append(';');
        return s.toString();
    }

    static boolean isIp(String v) {
        return v.matches("\\d{1,3}(\\.\\d{1,3}){3}(/\\d{1,2})?");
    }

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
