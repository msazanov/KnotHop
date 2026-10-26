package com.knothop.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Снимок состояния для экрана маршрутизации: фаза VPN, текущий выход, выбор пользователя на главном экране (файл state/select),
 * доступность выходов и данные маршрутизации из state/status.json. Только чтение; решений о правах и путях здесь нет.
 */
final class RoutingStatus {
    static final class Exit {
        final String dest, name, state, why;
        /** Мой Link к выходу не поднялся (lk=fail) или узел потерян: выход сейчас недоступен именно этому телефону. */
        final boolean unavailable;

        Exit(String dest, String name, String state, String why, boolean unavailable) {
            this.dest = dest;
            this.name = name;
            this.state = state;
            this.why = why;
            this.unavailable = unavailable;
        }
    }

    /** VPN включается или работает: только тогда status.json описывает настоящее состояние. */
    final boolean active;
    /** Фаза error: нативная часть остановилась, трафик заблокирован. */
    final boolean error;
    final boolean haveData;
    /** Список выходов из status.json как есть: для кэша известных узлов (RoutingCfg.cacheNodes). */
    final JSONArray exitsRaw;
    final String currentDest, currentName, selectedDest;
    final Map<String, Exit> exits = new LinkedHashMap<>();
    final List<String> backendWarnings = new ArrayList<>();
    final Map<String, Long> extraAge = new HashMap<>();
    final List<String> pending = new ArrayList<>();
    final boolean rulesOn;
    final long extraPkts, fallbackPkts;

    private RoutingStatus(boolean active, boolean error, JSONObject j, String selected) {
        this.active = active;
        this.error = error;
        this.haveData = j != null;
        String cd = "", cn = "";
        boolean on = false;
        long ex = 0, fb = 0;
        JSONArray raw = null;
        if (j != null) {
            JSONObject cur = j.optJSONObject("current");
            if (cur != null) {
                cd = cur.optString("d");
                cn = cur.optString("n");
            }
            JSONArray ea = j.optJSONArray("exits");
            raw = ea;
            for (int i = 0; ea != null && i < ea.length(); i++) {
                JSONObject e = ea.optJSONObject(i);
                if (e == null || !e.optString("d").matches("[0-9a-f]{32}")) continue;
                String st = e.optString("s");
                boolean fail = "fail".equals(e.optString("lk"));
                if ("current".equals(st) && cd.isEmpty()) {
                    cd = e.optString("d");
                    cn = e.optString("n");
                }
                String why = e.isNull("why") ? "" : e.optString("why");
                exits.put(e.optString("d"), new Exit(e.optString("d"), e.optString("n"), st, why, fail || "lost".equals(st)));
            }
            JSONObject r = j.optJSONObject("routing");
            if (r != null) {
                on = r.optBoolean("on");
                ex = r.optLong("extra_pkts");
                fb = r.optLong("fallback_pkts") + r.optLong("direct_fallback_pkts");
                JSONArray xs = r.optJSONArray("extras");
                for (int i = 0; xs != null && i < xs.length(); i++) {
                    JSONObject x = xs.optJSONObject(i);
                    if (x != null) extraAge.put(x.optString("d"), x.optLong("age_s"));
                }
                JSONArray ps = r.optJSONArray("pending");
                for (int i = 0; ps != null && i < ps.length(); i++) pending.add(ps.optString(i));
                JSONObject rep = r.optJSONObject("report");
                JSONArray w = rep == null ? null : rep.optJSONArray("warnings");
                for (int i = 0; w != null && i < w.length() && i < 6; i++) backendWarnings.add(w.optString(i));
            }
        }
        exitsRaw = raw;
        currentDest = cd;
        currentName = cn;
        rulesOn = on;
        extraPkts = ex;
        fallbackPkts = fb;
        selectedDest = selected;
    }

    static RoutingStatus read(File state) {
        String phase = KnotHopVpnService.phase;
        boolean active = "up".equals(phase) || "connecting".equals(phase);
        JSONObject j = null;
        String sel = "";
        if (active) {
            try {
                String js = Util.read(new File(state, "status.json"));
                if (!js.isEmpty()) j = new JSONObject(js);
            } catch (Throwable ignored) { }
            String s = Util.read(new File(state, "select")).trim();
            if (s.matches("[0-9a-f]{32}")) sel = s;
        }
        return new RoutingStatus(active, "error".equals(phase), j, sel);
    }

    /** Выход сейчас недоступен этому телефону (только по данным живого статуса). */
    boolean unavailable(String dest) {
        Exit e = exits.get(dest);
        return active && e != null && e.unavailable;
    }

    /** Выбор на главном экране задан и отличается от текущего выхода. */
    boolean selectedButNotUsed() {
        return !selectedDest.isEmpty() && !selectedDest.equals(currentDest);
    }
}
