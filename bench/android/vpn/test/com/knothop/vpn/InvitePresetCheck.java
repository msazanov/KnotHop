package com.knothop.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

/** Пресеты приглашения только заполняют права; ручная правка = «Свои»; права на чужой ноде не выше моих; тексты P2P. */
public final class InvitePresetCheck {
    private static void eq(Object a, Object b, String what) { if (!a.equals(b)) throw new AssertionError(what + ": " + a + " != " + b); }

    public static void main(String[] args) throws Exception {
        eq(Rights.presetRights(Rights.P_SERVER), Rights.USE, "сервер: права получателя");
        eq(Rights.presetMgmt(Rights.P_SERVER), Rights.CONFIG | Rights.ADD | Rights.REMOVE | Rights.USE, "сервер: управление получателем");
        eq(Rights.presetRights(Rights.P_USER), Rights.USE, "пользователь");
        eq(Rights.presetMgmt(Rights.P_USER), 0, "пользователь: без управления");
        eq(Rights.presetRights(Rights.P_ADMIN), Rights.CONFIG | Rights.ADD | Rights.REMOVE | Rights.USE, "админ");
        eq(Rights.presetMgmt(Rights.P_ADMIN), 0, "админ: без управления");
        // сочетание, которого нет среди пресетов, - «Свои»
        eq(Rights.presetFor(Rights.USE | Rights.HOST_ACCESS, 0), Rights.P_CUSTOM, "ручная правка");
        eq(Rights.presetFor(Rights.USE, 0), Rights.P_USER, "совпало с пользователем");
        eq(Rights.presetFor(Rights.USE, Rights.ADMIN), Rights.P_SERVER, "совпало с сервером");
        // чужая нода: ADD без CONFIG ограничен моими правами, CONFIG - нет
        eq(Rights.exceeds(Rights.USE | Rights.CONFIG, Rights.USE | Rights.ADD), Rights.CONFIG, "выше моих прав");
        eq(Rights.exceeds(Rights.USE | Rights.ADD, Rights.USE | Rights.ADD), 0, "в пределах");
        eq(Rights.exceeds(Rights.ADMIN | Rights.HOST_ACCESS, Rights.CONFIG), 0, "CONFIG без ограничений");
        // P2P: тексты и сводка
        JSONArray a = new JSONArray()
            .put(new JSONObject().put("state", "direct").put("rtt_ms", 12.4).put("n", "pixel").put("id", "aabbccddeeff00112233445566778899"))
            .put(new JSONObject().put("state", "no_addr").put("n", "ПК").put("id", "00112233445566778899aabbccddeeff"))
            .put(new JSONObject().put("state", "unreachable").put("n", "x").put("id", "112233445566778899aabbccddeeff00"))
            .put(new JSONObject().put("state", "trying").put("n", "y").put("id", "2233445566778899aabbccddeeff0011"));
        eq(P2p.text(a.getJSONObject(0)), "Прямое соединение установлено (QUIC, 12 мс)", "direct");
        eq(P2p.text(a.getJSONObject(1)), "Прямое соединение с ПК не удалось: нет адреса", "no_addr");
        eq(P2p.text(a.getJSONObject(2)), "Прямое соединение с x не удалось: не отвечает: устройства за NAT, нужен узел-посредник или IPv6", "unreachable");
        if (!P2p.text(a.getJSONObject(3)).startsWith("Пробую")) throw new AssertionError("trying");
        P2p.Summary s = P2p.summary(a);
        eq(s.direct + "/" + s.total + "/" + s.failed, "1/4/2", "сводка");
        System.out.println("InvitePresetCheck PASS");
    }
}
