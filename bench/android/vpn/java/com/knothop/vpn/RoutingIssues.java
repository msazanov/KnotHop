package com.knothop.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Предупреждения экрана маршрутизации: недостающие файлы списков, правила без категории, недоступные или неизвестные выходы,
 * неподдерживаемое «мимо VPN», расхождение с тем, что применено при подключении. Считает только по данным, которые уже есть в
 * приложении; новых возможностей нативной части не предполагает.
 */
final class RoutingIssues {
    static final class Issue {
        final boolean warn;
        final String text;
        Issue(boolean warn, String text) { this.warn = warn; this.text = text; }
    }

    private RoutingIssues() { }

    /**
     * @param catalog содержимое rules-cats.json или null, если списки ещё не разобраны
     * @param appliedDirectSig подпись правил «мимо VPN», применённая при последнем подключении
     */
    static List<Issue> collect(RoutingCfg cfg, RoutingStatus st, RoutingLabels lb, boolean filesPresent, JSONObject catalog, String appliedDirectSig) {
        List<Issue> out = new ArrayList<>();
        if (cfg.corrupt) out.add(new Issue(true, "Файл настроек маршрутизации повреждён и сейчас игнорируется. Первое изменение на этом экране заменит его."));
        if (st.error) out.add(new Issue(true, "VPN остановлен из-за ошибки, трафик заблокирован. Отключите и снова включите VPN на главном экране."));
        if (!cfg.mode.equals(RoutingCfg.MODE_RULES)) return out;

        boolean anyList = false, anyDirect = false;
        for (RoutingCfg.Rule r : cfg.rules) {
            if (!r.enabled) continue;
            anyList = true;
            if (!r.valid()) {
                out.add(new Issue(true, "Правило «" + clip(r.name) + "» не распознано и не применяется."));
                continue;
            }
            if (r.action.equals("direct")) anyDirect = true;
            if (r.directUnsupported()) out.add(new Issue(true, "«" + clip(r.name) + "»: «мимо VPN» для сайтов не работает, трафик пойдёт через выход по умолчанию."));
            if (filesPresent && catalog != null && !inCatalog(catalog, r)) {
                out.add(new Issue(true, "В загруженных списках нет категории «" + clip(r.name) + "»: правило не применяется. Обновите списки или удалите правило."));
            }
        }
        if (anyList && !filesPresent) {
            out.add(new Issue(true, "Списки не загружены: правила по спискам не действуют, трафик идёт через выход по умолчанию. Скачайте списки."));
        }
        for (RoutingCfg.Manual m : cfg.manual) {
            if (!m.enabled) continue;
            if (!m.valid() || RoutingCfg.cleanManual(m.value) == null) {
                out.add(new Issue(true, "Запись «" + clip(m.value) + "» не распознана и не применяется."));
                continue;
            }
            if (m.action.equals("direct")) anyDirect = true;
            if (m.directUnsupported()) out.add(new Issue(true, "«" + clip(m.value) + "»: «мимо VPN» для доменов не работает, трафик пойдёт через выход по умолчанию."));
        }

        // выходы правил: по одному предупреждению на выход
        Map<String, Integer> uses = new LinkedHashMap<>();
        for (RoutingCfg.Rule r : cfg.rules) if (r.enabled && r.valid() && r.action.startsWith("exit:")) bump(uses, r.action.substring(5));
        for (RoutingCfg.Manual m : cfg.manual) if (m.enabled && m.valid() && m.action.startsWith("exit:")) bump(uses, m.action.substring(5));
        for (Map.Entry<String, Integer> e : uses.entrySet()) {
            String d = e.getKey().toLowerCase(Locale.ROOT);
            String who = lb.nameOf(d);
            if (!lb.known(d)) {
                out.add(new Issue(true, "Выход " + who + " не найден среди известных (правил: " + e.getValue() + "). До его появления трафик этих правил не отправляется через другие ноды."));
            } else if (st.unavailable(d)) {
                out.add(new Issue(true, "Выход " + who + " сейчас недоступен (правил: " + e.getValue() + "). Восстанавливаем путь к нему; подмена другим выходом запрещена."));
            } else if (st.active && st.haveData && !d.equals(st.currentDest) && !st.extraAge.containsKey(d) && !st.pending.contains(d)) {
                out.add(new Issue(false, "Дополнительное соединение с выходом " + who + " ещё не поднято (правил: " + e.getValue() + ")."));
            }
        }

        if (anyDirect) {
            out.add(new Issue(true, "Есть правила «Мимо VPN»: этот трафик идёт напрямую, туннель и защита от сбоя VPN его не охватывают."));
        }
        if (st.active && !cfg.directSig().equals(appliedDirectSig)) {
            out.add(new Issue(true, "Правила «мимо VPN» изменились: отключите и снова включите VPN, чтобы они вступили в силу."));
        }
        for (String w : st.backendWarnings) {
            // «нет файла списков» и «нет такой категории» уже показаны выше с понятным действием
            if (w.contains("нет файла списков") || w.contains("нет такой категории")) continue;
            out.add(new Issue(true, w));
        }
        if (cfg.enabledRules() == 0) {
            out.add(new Issue(false, "Включённых правил нет: весь трафик идёт через выход по умолчанию."));
        }
        return out;
    }

    private static void bump(Map<String, Integer> m, String k) {
        Integer v = m.get(k);
        m.put(k, v == null ? 1 : v + 1);
    }

    private static String clip(String s) {
        if (s == null) return "";
        return s.length() > 40 ? s.substring(0, 40) + "…" : s;
    }

    private static boolean inCatalog(JSONObject cats, RoutingCfg.Rule r) {
        JSONArray a = cats.optJSONArray(r.type);
        if (a == null || a.length() == 0) return true;   // каталог этого вида пуст или не разобран: не выдумываем отсутствие
        for (int i = 0; i < a.length(); i++) {
            JSONArray e = a.optJSONArray(i);
            if (e != null && e.optString(0).equalsIgnoreCase(r.name)) return true;
        }
        return false;
    }
}
