package com.knothop.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

/** Пресеты приглашения только заполняют права; ручная правка = «Свои»; права на чужой ноде не выше моих; тексты P2P. */
public final class InvitePresetCheck {
    private static void eq(Object a, Object b, String what) { if (!a.equals(b)) throw new AssertionError(what + ": " + a + " != " + b); }

    public static void main(String[] args) throws Exception {
        // один набор флагов: права получателя на выпустившей ноде; управления получателем в пресетах нет
        eq(Rights.presetRights(Rights.P_USER), Rights.USE, "пользователь = USE");
        eq(Rights.presetRights(Rights.P_SERVER), Rights.USE, "сервер = USE (признание админа - свойство запуска сервера)");
        eq(Rights.presetRights(Rights.P_ADMIN), Rights.CONFIG | Rights.ADD | Rights.REMOVE | Rights.USE, "админ");
        eq(Rights.presetRights(Rights.P_CUSTOM), 0, "свои: значение остаётся ручным");
        eq(Rights.PRESET_NAMES.length, 4, "четыре пресета");
        eq(Rights.PRESET_NAMES[Rights.P_USER] + "/" + Rights.PRESET_NAMES[Rights.P_SERVER] + "/" + Rights.PRESET_NAMES[Rights.P_ADMIN] + "/" + Rights.PRESET_NAMES[Rights.P_CUSTOM],
                "Пользователь/Сервер/Админ/Свои", "порядок и подписи");
        if (!Rights.PRESET_HINTS[Rights.P_SERVER].contains("признает вас админом")) throw new AssertionError("подсказка сервера");
        // сочетание, которого нет среди пресетов, - «Свои»; при равных правах «Пользователь» и «Сервер» берётся «Пользователь»
        eq(Rights.presetFor(Rights.USE | Rights.HOST_ACCESS), Rights.P_CUSTOM, "ручная правка");
        eq(Rights.presetFor(Rights.USE), Rights.P_USER, "совпало с пользователем");
        eq(Rights.presetFor(Rights.ADMIN), Rights.P_ADMIN, "совпало с админом");
        // сетка пресетов и срока: 2 столбца, плитки равной ширины, последняя строка неполной сетки не растягивается
        eq(java.util.Arrays.deepToString(ChoiceGrid.layout(4, 2)), "[[0, 1], [2, 3]]", "сетка 2x2");
        eq(java.util.Arrays.deepToString(ChoiceGrid.layout(3, 2)), "[[0, 1], [2]]", "неполная последняя строка");
        eq(java.util.Arrays.deepToString(ChoiceGrid.layout(1, 2)), "[[0]]", "одна плитка");
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
        eq(P2p.text(new JSONObject().put("state", "direct").put("rtt_ms", 3.2).put("lan", true)), "Прямое соединение установлено (QUIC, локальная сеть, 3 мс)", "direct по локальной сети");
        eq(P2p.graphLines("direct", 7.4, true)[0], "прямое QUIC (локальная сеть), 7 мс", "граф: локальная сеть");
        eq(P2p.graphLines("direct", 7.4, false)[0], "прямое QUIC, 7 мс", "граф: обычный прямой");
        eq(P2p.label(new JSONObject().put("n", "pixel").put("id", "aabbccddeeff00112233445566778899")), "pixel  aabbccdd", "имя и короткий хеш");
        eq(P2p.label(new JSONObject().put("n", "").put("id", "aabbccddeeff00112233445566778899")), "aabbccdd", "без имени - только хеш, без дубля");
        eq(P2p.label(new JSONObject().put("n", "aabbccdd").put("id", "aabbccddeeff00112233445566778899")), "aabbccdd", "имя = хеш - без дубля");
        eq(P2p.text(a.getJSONObject(1)), "Прямое соединение с ПК не удалось: нет адреса", "no_addr");
        eq(P2p.text(a.getJSONObject(2)), "Прямое соединение с x не удалось: не отвечает: устройства за NAT, нужен узел-посредник или IPv6", "unreachable");
        if (!P2p.text(a.getJSONObject(3)).startsWith("Пробую")) throw new AssertionError("trying");
        P2p.Summary s = P2p.summary(a);
        eq(s.direct + "/" + s.total + "/" + s.failed, "1/4/2", "сводка");
        System.out.println("InvitePresetCheck PASS");
    }
}
