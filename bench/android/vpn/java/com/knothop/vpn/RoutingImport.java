package com.knothop.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Импорт правил в формате v2rayN / Xray: массив объектов {enabled, outboundTag, domain[], ip[], remarks, ...} (или объект с "rules",
 * или целый конфиг с "routing":{"rules":[...]}). Те же имена категорий geoip:/geosite:, что в файлах списков проекта.
 *
 * <p>Переносится только то, что умеет маршрутизация клиента: outboundTag direct и proxy (proxy = выход по умолчанию) и условия
 * domain/ip (geosite:, geoip:, domain:, full:, keyword:, адреса и подсети). Остальное (block, protocol, network, port, regexp:,
 * инверсии и атрибуты geosite) пропускается и перечисляется в отчёте: молча терять правила нельзя.
 */
final class RoutingImport {
    static final class Result {
        final List<RoutingCfg.Rule> rules = new ArrayList<>();
        final List<RoutingCfg.Manual> manual = new ArrayList<>();
        final List<String> skipped = new ArrayList<>();
        /** Правила для сайтов с действием «мимо VPN»: мимо туннеля работают только подсети, сайты пойдут через выход по умолчанию. */
        int siteDirect;

        int count() { return rules.size() + manual.size(); }
    }

    private RoutingImport() { }

    /** Исключение с понятным текстом, если это не JSON-массив правил. */
    static Result parse(String text) throws Exception {
        String t = text == null ? "" : text.trim();
        if (t.isEmpty()) throw new Exception("пусто");
        if (t.length() > 256 * 1024) throw new Exception("слишком длинный текст");
        JSONArray arr;
        if (t.startsWith("[")) {
            arr = new JSONArray(t);
        } else {
            JSONObject o = new JSONObject(t);
            JSONObject r = o.optJSONObject("routing");
            arr = (r != null ? r : o).optJSONArray("rules");
            if (arr == null) throw new Exception("нет массива rules");
        }
        Result res = new Result();
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.optJSONObject(i);
            if (o == null) continue;
            one(res, o, i + 1);
        }
        return res;
    }

    private static String label(JSONObject o, int n) {
        String r = o.optString("remarks", "").trim();
        return r.isEmpty() ? "правило " + n : "«" + (r.length() > 40 ? r.substring(0, 40) + "…" : r) + "»";
    }

    private static void one(Result res, JSONObject o, int n) {
        String lab = label(o, n);
        String tag = o.optString("outboundTag", "").toLowerCase(Locale.ROOT);
        String action;
        if (tag.equals("direct")) action = "direct";
        else if (tag.equals("proxy")) action = "default";
        else if (tag.equals("block")) { res.skipped.add(lab + ": блокировка (block) не поддерживается"); return; }
        else { res.skipped.add(lab + ": выход «" + tag + "» не поддерживается"); return; }
        for (String k : new String[]{"protocol", "network", "port", "sourcePort", "source", "inboundTag", "user", "attrs"}) {
            if (o.has(k) && !isEmpty(o.opt(k))) { res.skipped.add(lab + ": условие «" + k + "» не поддерживается"); return; }
        }
        JSONArray dom = o.optJSONArray("domain"), ip = o.optJSONArray("ip");
        if (dom != null && dom.length() > 0 && ip != null && ip.length() > 0) {
            res.skipped.add(lab + ": одновременные условия domain и ip (AND) не поддерживаются");
            return;
        }
        if ((dom == null || dom.length() == 0) && (ip == null || ip.length() == 0)) {
            res.skipped.add(lab + ": нет условий domain/ip");
            return;
        }
        boolean enabled = o.optBoolean("enabled", true);
        int before = res.count(), bad = 0;
        for (int i = 0; dom != null && i < dom.length(); i++) {
            String s = dom.optString(i, "").trim();
            if (s.toLowerCase(Locale.ROOT).startsWith("geosite:")) {
                String name = s.substring(8).trim();
                if (!listName(name)) { bad++; continue; }
                RoutingCfg.Rule r = new RoutingCfg.Rule("geosite", name, action);
                r.enabled = enabled;
                res.rules.add(r);
                if (action.equals("direct") && enabled) res.siteDirect++;
            } else {
                String ok = RoutingCfg.cleanManual(s);
                if (ok == null) { bad++; continue; }
                RoutingCfg.Manual m = new RoutingCfg.Manual(ok, action);
                m.enabled = enabled;
                res.manual.add(m);
                if (action.equals("direct") && enabled && !RoutingCfg.isIp(ok)) res.siteDirect++;
            }
        }
        for (int i = 0; ip != null && i < ip.length(); i++) {
            String s = ip.optString(i, "").trim();
            if (s.toLowerCase(Locale.ROOT).startsWith("geoip:")) {
                String name = s.substring(6).trim();
                if (!listName(name)) { bad++; continue; }
                RoutingCfg.Rule r = new RoutingCfg.Rule("geoip", name, action);
                r.enabled = enabled;
                res.rules.add(r);
            } else if (RoutingCfg.isIp(s)) {
                RoutingCfg.Manual m = new RoutingCfg.Manual(s, action);
                m.enabled = enabled;
                res.manual.add(m);
            } else {
                bad++;
            }
        }
        if (bad > 0) res.skipped.add(lab + ": не распознано условий: " + bad + " (regexp:, инверсия, атрибуты и т. п.)");
        if (res.count() == before && bad == 0) res.skipped.add(lab + ": ничего не перенесено");
    }

    private static boolean isEmpty(Object v) {
        if (v == null || v == JSONObject.NULL) return true;
        if (v instanceof JSONArray) return ((JSONArray) v).length() == 0;
        return v.toString().trim().isEmpty();
    }

    /** Имя категории из файла списков: без инверсии (!), атрибутов (@) и посторонних знаков. */
    private static boolean listName(String n) {
        return n.length() > 0 && n.length() <= 80 && n.matches("[A-Za-z0-9._-]+");
    }

    /**
     * Добавляет результат в настройки (повтор с тем же видом и именем обновляет действие). Включает режим «По правилам».
     * Возвращает число добавленных или обновлённых записей; предел записей отбрасывает остальное.
     */
    static int apply(RoutingCfg cfg, Result r) {
        int done = 0;
        for (RoutingCfg.Rule x : r.rules) {
            boolean dup = false;
            for (RoutingCfg.Rule e : cfg.rules) {
                if (e.type.equals(x.type) && e.name.equalsIgnoreCase(x.name)) { e.action = x.action; e.enabled = x.enabled; dup = true; break; }
            }
            if (!dup) {
                if (cfg.rules.size() >= RoutingCfg.MAX_RULES) continue;
                cfg.rules.add(x);
            }
            done++;
        }
        for (RoutingCfg.Manual x : r.manual) {
            boolean dup = false;
            for (RoutingCfg.Manual e : cfg.manual) {
                if (e.value.equalsIgnoreCase(x.value)) { e.action = x.action; e.enabled = x.enabled; dup = true; break; }
            }
            if (!dup) {
                if (cfg.manual.size() >= RoutingCfg.MAX_MANUAL) continue;
                cfg.manual.add(x);
            }
            done++;
        }
        if (done > 0) cfg.mode = RoutingCfg.MODE_RULES;
        return done;
    }

    // ---------------------------------------------------------------- шаблоны

    static final class Template {
        final String title, note, json;
        Template(String title, String note, String json) { this.title = title; this.note = note; this.json = json; }
    }

    /** Локальные сети задаются подсетями, поэтому работают без файлов списков. */
    static final Template[] TEMPLATES = {
        new Template("Локальные сети напрямую",
                "Адреса домашней и рабочей сети (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16) идут мимо VPN. Файлы списков не нужны. Применяется при следующем подключении в режиме «VPN».",
                "[{\"enabled\":true,\"outboundTag\":\"direct\",\"remarks\":\"Direct LAN\",\"ip\":[\"10.0.0.0/8\",\"172.16.0.0/12\",\"192.168.0.0/16\",\"169.254.0.0/16\"]}]"),
        new Template("Россия напрямую",
                "Сайты и адреса из списков geosite:category-ru и geoip:ru идут мимо VPN, остальное через выход. Нужны файлы списков. Мимо VPN работают только адреса (geoip), сайты пойдут через выход по умолчанию.",
                "[{\"enabled\":true,\"outboundTag\":\"direct\",\"remarks\":\"Bypass Russia domains\",\"domain\":[\"geosite:category-ru\"]},"
                        + "{\"enabled\":true,\"outboundTag\":\"direct\",\"remarks\":\"Bypass Russia IP\",\"ip\":[\"geoip:ru\"]}]"),
        new Template("Набор v2rayN (РФ)",
                "Стандартный набор правил v2rayN для России: локальные сети (geoip:private, geosite:private) и российские сайты и адреса напрямую. Правила bittorrent и block UDP 443 не поддерживаются и будут пропущены.",
                "[{\"enabled\":true,\"locked\":false,\"outboundTag\":\"direct\",\"protocol\":[\"bittorrent\"],\"remarks\":\"Bypass bittorrent\"},"
                        + "{\"enabled\":true,\"locked\":false,\"network\":\"udp\",\"outboundTag\":\"block\",\"port\":\"443\",\"remarks\":\"Block udp443\"},"
                        + "{\"enabled\":true,\"ip\":[\"geoip:private\"],\"locked\":false,\"outboundTag\":\"direct\",\"remarks\":\"Direct LAN IP\"},"
                        + "{\"domain\":[\"geosite:private\"],\"enabled\":true,\"locked\":false,\"outboundTag\":\"direct\",\"remarks\":\"Direct LAN domains\"},"
                        + "{\"domain\":[\"geosite:category-ru\"],\"enabled\":true,\"locked\":false,\"outboundTag\":\"direct\",\"remarks\":\"Bypass Russia domains\"},"
                        + "{\"enabled\":true,\"ip\":[\"geoip:ru\"],\"locked\":false,\"outboundTag\":\"direct\",\"remarks\":\"Bypass Russia IP\"}]"),
    };
}
