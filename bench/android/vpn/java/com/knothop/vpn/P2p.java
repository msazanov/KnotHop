package com.knothop.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Прямая связь с контактами без серверов (P2P, status.json → {@code p2p}). Состояния ядра: {@code direct} (QUIC установлен),
 * {@code no_addr} (адреса нет), {@code unreachable} (не отвечает: за NAT нужен посредник или IPv6), {@code trying} (первые попытки).
 * Тексты говорят прямо, что получилось и что нет; «подключаюсь…» не показывается бесконечно: после двух неудач ядро сообщает {@code unreachable}.
 */
final class P2p {
    private P2p() { }

    static final class Summary {
        int direct, total, failed;
    }

    static Summary summary(JSONArray p2p) {
        Summary s = new Summary();
        for (int i = 0; p2p != null && i < p2p.length(); i++) {
            JSONObject e = p2p.optJSONObject(i);
            if (e == null) continue;
            s.total++;
            String st = e.optString("state");
            if ("direct".equals(st)) s.direct++;
            else if ("no_addr".equals(st) || "unreachable".equals(st)) s.failed++;
        }
        return s;
    }

    static String name(JSONObject e) {
        String n = Rights.clip(e.optString("n", ""));
        String id = e.optString("id", "");
        if (n.isEmpty() || "?".equals(n)) n = id.length() >= 8 ? id.substring(0, 8) : "?";
        return n;
    }

    /** Полная фраза для экрана «Сеть». */
    static String text(JSONObject e) {
        String who = name(e);
        switch (e.optString("state")) {
            case "direct": return "Прямое соединение установлено (QUIC" + (e.isNull("rtt_ms") ? "" : ", " + Math.round(e.optDouble("rtt_ms")) + " мс") + ")";
            case "no_addr": return "Прямое соединение с " + who + " не удалось: нет адреса";
            case "unreachable": return "Прямое соединение с " + who + " не удалось: не отвечает: устройства за NAT, нужен узел-посредник или IPv6";
            default: return "Пробую прямое соединение с " + who + "…";
        }
    }

    /** Что с этим соединением можно сделать (только при установленной связи). */
    static String capability(JSONObject e) {
        return "direct".equals(e.optString("state")) ? "Связь есть; выход в интернет через это устройство — только если на нём включён EXIT." : "";
    }

    static boolean failed(JSONObject e) {
        String st = e.optString("state");
        return "no_addr".equals(st) || "unreachable".equals(st);
    }

    /** Две короткие строки под узлом графа: {второй ряд, третий ряд}. */
    static String[] graphLines(String state, double rtt) {
        switch (state) {
            case "direct": return new String[]{"прямое QUIC" + (rtt >= 0 ? ", " + Math.round(rtt) + " мс" : ""), "выход — только при EXIT"};
            case "no_addr": return new String[]{"прямое не удалось: нет адреса", ""};
            case "unreachable": return new String[]{"прямое не удалось: не отвечает", "за NAT: нужен посредник или IPv6"};
            default: return new String[]{"пробую прямое соединение…", ""};
        }
    }
}
