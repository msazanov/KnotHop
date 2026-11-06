package com.knothop.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Связь с контактами без серверов (P2P, status.json → {@code p2p}). Состояния ядра: {@code direct}, {@code mesh}, {@code relay},
 * {@code reality} (выбранный путь QUIC),
 * {@code no_addr} (адреса нет), {@code unreachable} (устройство или путь недоступны), {@code trying} (первые попытки).
 * Тексты говорят прямо, что получилось и что нет; «подключаюсь…» не показывается бесконечно: после двух неудач ядро сообщает {@code unreachable}.
 */
final class P2p {
    private P2p() { }

    static final class Summary {
        int connected, direct, total, failed;
    }

    static boolean connected(String state) {
        return "direct".equals(state) || "mesh".equals(state) || "relay".equals(state) || "reality".equals(state);
    }

    static Summary summary(JSONArray p2p) {
        Summary s = new Summary();
        for (int i = 0; p2p != null && i < p2p.length(); i++) {
            JSONObject e = p2p.optJSONObject(i);
            if (e == null) continue;
            s.total++;
            String st = e.optString("state");
            if (connected(st)) {
                s.connected++;
                if ("direct".equals(st)) s.direct++;
            } else if ("no_addr".equals(st) || "unreachable".equals(st)) s.failed++;
        }
        return s;
    }

    /** Имя контакта (если есть) и короткий хеш: «pixel  aabbccdd»; без имени - только хеш. */
    static String label(JSONObject e) {
        String n = Rights.clip(e.optString("n", ""));
        String id = e.optString("id", "");
        String h = id.length() >= 8 ? id.substring(0, 8) : "";
        if (n.isEmpty() || "?".equals(n) || n.equals(h)) return h.isEmpty() ? "?" : h;
        return h.isEmpty() ? n : n + "  " + h;
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
        String rtt = e.isNull("rtt_ms") ? "" : ", " + Math.round(e.optDouble("rtt_ms")) + " мс";
        switch (e.optString("state")) {
            case "direct": return "Прямое соединение установлено (QUIC" + (e.optBoolean("lan") ? ", локальная сеть" : "") + rtt + ")";
            case "mesh": return "Соединение с " + who + " установлено (QUIC через mesh" + rtt + ")";
            case "relay": return "Соединение с " + who + " установлено (QUIC через relay" + rtt + ")";
            case "reality": return "Соединение с " + who + " установлено (QUIC через REALITY" + rtt + ")";
            case "no_addr": return "Прямое соединение с " + who + " не удалось: нет адреса";
            case "unreachable": return "Прямое соединение с " + who + " не удалось: устройство не отвечает или путь недоступен";
            default: return "Пробую прямое соединение с " + who + "…";
        }
    }

    /** Что с этим соединением можно сделать (только при установленной связи). */
    static String capability(JSONObject e) {
        return connected(e.optString("state")) ? "Связь есть; выход в интернет через это устройство — только если на нём включён EXIT." : "";
    }

    static boolean failed(JSONObject e) {
        String st = e.optString("state");
        return "no_addr".equals(st) || "unreachable".equals(st);
    }

    /** Две короткие строки под узлом графа: {второй ряд, третий ряд}. */
    static String[] graphLines(String state, double rtt, boolean lan) {
        switch (state) {
            case "direct": return new String[]{"прямое QUIC" + (lan ? " (локальная сеть)" : "") + (rtt >= 0 ? ", " + Math.round(rtt) + " мс" : ""), "выход — только при EXIT"};
            case "mesh": return new String[]{"QUIC через mesh" + (rtt >= 0 ? ", " + Math.round(rtt) + " мс" : ""), "выход — только при EXIT"};
            case "relay": return new String[]{"QUIC через relay" + (rtt >= 0 ? ", " + Math.round(rtt) + " мс" : ""), "выход — только при EXIT"};
            case "reality": return new String[]{"QUIC через REALITY" + (rtt >= 0 ? ", " + Math.round(rtt) + " мс" : ""), "выход — только при EXIT"};
            case "no_addr": return new String[]{"прямое не удалось: нет адреса", ""};
            case "unreachable": return new String[]{"прямое не удалось: нет ответа", "устройство или путь недоступны"};
            default: return new String[]{"пробую прямое соединение…", ""};
        }
    }
}
