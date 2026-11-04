package com.knothop.vpn;

/** JVM-only: пресеты маршрутизации как данные, сохранение своих правил, фильтр выходов. */
public final class RoutingPresetsCheck {
    private static void check(boolean ok, String why) { if (!ok) throw new AssertionError(why); }

    public static void main(String[] args) throws Exception {
        RoutingCfg c = new RoutingCfg();
        c.manual.add(new RoutingCfg.Manual("example.org", "default"));
        c.rules.add(new RoutingCfg.Rule("geosite", "youtube", "default"));
        RoutingPresets.apply(c, RoutingPresets.BLOCKED);
        check(c.mode.equals("rules") && c.splitInclude() && c.preset().equals("blocked"), "blocked: rules + include");
        check(c.manual.get(0).value.equals("example.org") && c.rules.get(0).name.equals("youtube"), "custom rules stay first");
        check(RoutingPresets.customCount(c) == 2, "custom count");
        RoutingPresets.apply(c, RoutingPresets.RU_DIRECT);
        check(!c.splitInclude() && c.rules.stream().noneMatch(r -> r.name.equals("RU-BLOCKED")), "switching preset removes the previous preset entries");
        check(c.rules.stream().anyMatch(r -> r.name.equals("ru") && r.action.equals("direct")), "ru direct list");
        check(RoutingPresets.customCount(c) == 2, "custom rules survive");
        RoutingPresets.apply(c, RoutingPresets.ALL_DIRECT);
        check(c.mode.equals("auto") && c.directSig().equals("all-direct") && c.rules.size() == 1, "direct: no preset rules, auto mode");
        RoutingPresets.apply(c, RoutingPresets.ALL_TUNNEL);
        check(c.mode.equals("rules"), "tunnel with custom rules keeps rules mode");
        RoutingCfg plain = new RoutingCfg();
        RoutingPresets.apply(plain, RoutingPresets.ALL_TUNNEL);
        check(plain.mode.equals("auto") && plain.rules.isEmpty() && plain.manual.isEmpty(), "tunnel: plain auto");
        plain.setExitFilter(true, java.util.Arrays.asList(" Россия ", "RUSSIA", ""));
        RoutingCfg back = RoutingCfg.parse(plain.toJson().toString());
        check(back.filterExclude() && back.filterWords().equals(java.util.Arrays.asList("россия", "russia")), "filter round-trip");
        check(back.exitFilterSummary().equals("без: россия, russia"), "summary");
        RoutingCfg b2 = new RoutingCfg();
        RoutingPresets.apply(b2, RoutingPresets.BLOCKED);
        check(RoutingCfg.parse(b2.toJson().toString()).splitInclude(), "split survives save/load");
        System.out.println("RoutingPresetsCheck PASS");
    }
}
