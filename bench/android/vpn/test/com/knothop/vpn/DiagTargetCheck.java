package com.knothop.vpn;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** JVM-only: адрес диагностики остаётся в туннеле при всех пресетах и своих правилах «мимо VPN». */
public final class DiagTargetCheck {
    private static void check(boolean ok, String why) { if (!ok) throw new AssertionError(why); }

    static long size(String c) { return 1L << (32 - Integer.parseInt(c.substring(c.indexOf('/') + 1))); }

    public static void main(String[] args) throws Exception {
        long diag = DiagTarget.parseIp(DiagTarget.HOST);
        check(diag == 0x01000001L, "HOST 1.0.0.1");

        // вырезка: /8 без одного адреса, блоки не пересекаются и лежат внутри
        List<String> carved = DiagTarget.carveOut(Arrays.asList("1.0.0.0/8", "8.8.0.0/16", "1.0.0.1/32", "0.0.0.0/0"));
        check(carved.stream().noneMatch(c -> DiagTarget.contains(c, diag)), "диагностика не в списке «мимо»");
        check(carved.contains("8.8.0.0/16"), "посторонние подсети не тронуты");
        long total = 0;
        // отдельно: одна подсеть /8 -> ровно 24 блока, суммарно 2^24 - 1 адрес, адреса вне диагностики сохраняются
        List<String> one = DiagTarget.carveOut(Arrays.asList("1.0.0.0/8"));
        check(one.size() == 24, "24 блока: " + one.size());
        for (String c : one) total += size(c);
        check(total == (1L << 24) - 1, "покрыто 2^24-1 адрес");
        for (long probe : new long[]{0x01000000L, 0x01000002L, 0x01000100L, 0x01800000L, 0x01ffffffL})
            check(one.stream().filter(c -> DiagTarget.contains(c, probe)).count() == 1, "адрес остался ровно в одном блоке: " + DiagTarget.fmt(probe));
        check(DiagTarget.carveOut(Arrays.asList("1.0.0.1/32")).isEmpty(), "точный /32 удаляется");
        check(DiagTarget.carveOut(Arrays.asList("garbage", "1.0.0.0/33")).equals(Arrays.asList("garbage", "1.0.0.0/33")), "мусор не ломает");

        // все пресеты и своё правило direct 1.0.0.0/8
        String[] presets = {RoutingPresets.ALL_TUNNEL, RoutingPresets.ALL_DIRECT, RoutingPresets.BLOCKED, RoutingPresets.RU_DIRECT};
        for (String preset : presets) {
            for (boolean custom : new boolean[]{false, true}) {
                RoutingCfg c = new RoutingCfg();
                if (custom) c.manual.add(new RoutingCfg.Manual("1.0.0.0/8", "direct"));
                RoutingPresets.apply(c, preset);
                boolean allDirect = RoutingPresets.ALL_DIRECT.equals(c.preset());
                // как в службе: список «мимо» после вырезки; в режиме include - подсети без/с адресом диагностики
                List<String> direct = DiagTarget.carveOut(new ArrayList<>(Arrays.asList("1.0.0.0/8", "0.0.0.0/1", "10.0.0.0/8")));
                List<String> include = c.splitInclude() ? new ArrayList<>(Arrays.asList("91.108.4.0/22", "149.154.160.0/20")) : null;
                String tag = preset + (custom ? "+custom" : "");
                if (allDirect) check(!DiagTarget.routedToTunnel(true, null, direct), tag + ": «Всё напрямую» туннеля нет");
                else check(DiagTarget.routedToTunnel(false, include, direct), tag + ": диагностика в туннеле");
            }
        }
        // без вырезки модель должна видеть проблему (проверка самой проверки)
        check(!DiagTarget.routedToTunnel(false, null, Arrays.asList("1.0.0.0/8")), "без вырезки 1.0.0.0/8 перекрыл бы адрес");
        // include-режим: адрес всегда добавляется отдельным /32
        check(DiagTarget.routedToTunnel(false, new ArrayList<String>(), new ArrayList<String>()), "include с пустым списком: /32 диагностики есть");
        check(Arrays.asList(DiagTarget.INCLUDE_EXTRA).contains("1.0.0.1/32"), "INCLUDE_EXTRA содержит 1.0.0.1/32");

        // разбор trace
        String[] t = DiagTarget.parseTrace("fl=1\nh=1.0.0.1\nip=203.0.113.7\nloc=DE\ncolo=FRA\n");
        check(t[0].equals("203.0.113.7") && t[1].equals("DE"), "trace ip/loc");
        check(DiagTarget.parseTrace("x=1")[0].isEmpty(), "нет ip");
        check(DiagTarget.country("DE").endsWith("(DE)") && DiagTarget.country("").isEmpty(), "страна");
        System.out.println("DiagTargetCheck PASS");
    }
}
