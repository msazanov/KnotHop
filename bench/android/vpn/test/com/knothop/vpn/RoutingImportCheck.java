package com.knothop.vpn;

/** JVM-only: совместимый JSON, шаблоны и ограничения импорта. */
public final class RoutingImportCheck {
    private static void require(boolean ok, String why) { if (!ok) throw new AssertionError(why); }

    private static final String LAN = "[{\"enabled\":true,\"outboundTag\":\"direct\",\"remarks\":\"Direct LAN\",\"ip\":[\"10.0.0.0/8\",\"172.16.0.0/12\",\"192.168.0.0/16\",\"169.254.0.0/16\"]}]";
    private static final String RU = "[{\"enabled\":true,\"locked\":false,\"outboundTag\":\"direct\",\"protocol\":[\"bittorrent\"],\"remarks\":\"Bypass bittorrent\"},"
            + "{\"enabled\":true,\"locked\":false,\"network\":\"udp\",\"outboundTag\":\"block\",\"port\":\"443\",\"remarks\":\"Block udp443\"},"
            + "{\"enabled\":true,\"ip\":[\"geoip:private\"],\"locked\":false,\"outboundTag\":\"direct\",\"remarks\":\"Direct LAN IP\"},"
            + "{\"domain\":[\"geosite:private\"],\"enabled\":true,\"locked\":false,\"outboundTag\":\"direct\",\"remarks\":\"Direct LAN domains\"},"
            + "{\"domain\":[\"geosite:category-ru\"],\"enabled\":true,\"locked\":false,\"outboundTag\":\"direct\",\"remarks\":\"Bypass Russia domains\"},"
            + "{\"enabled\":true,\"ip\":[\"geoip:ru\"],\"locked\":false,\"outboundTag\":\"direct\",\"remarks\":\"Bypass Russia IP\"}]";

    public static void main(String[] args) throws Exception {
        RoutingImport.Result lan = RoutingImport.parse(LAN);
        require(lan.manual.size() == 4 && lan.rules.isEmpty() && lan.skipped.isEmpty(), "LAN without lists");
        RoutingImport.Result ru = RoutingImport.parse(RU);
        require(ru.count() == 4 && ru.skipped.size() == 2 && ru.siteDirect == 2, "compatible example: 4 imported, protocol/block skipped");
        RoutingCfg cfg = new RoutingCfg();
        require(RoutingImport.apply(cfg, ru) == 4 && cfg.mode.equals("rules"), "apply enables rules");
        RoutingImport.apply(cfg, ru);
        require(cfg.rules.size() == 4, "repeated import does not duplicate");
        RoutingImport.Result domain = RoutingImport.parse("{\"routing\":{\"rules\":[{\"outboundTag\":\"direct\",\"domain\":[\"domain:example.org\"]}]}}");
        require(domain.manual.size() == 1 && domain.siteDirect == 1, "manual direct domain warns too");
        RoutingImport.Result both = RoutingImport.parse("[{\"outboundTag\":\"direct\",\"domain\":[\"example.org\"],\"ip\":[\"192.0.2.0/24\"]}]");
        require(both.count() == 0 && both.skipped.size() == 1, "AND must not become OR");
        RoutingImport.Result disabled = RoutingImport.parse("[{\"enabled\":false,\"outboundTag\":\"proxy\",\"ip\":[\"192.0.2.0/24\"]}]");
        require(!disabled.manual.get(0).enabled && disabled.manual.get(0).action.equals("default"), "disabled proxy preserved");
        System.out.println("RoutingImportCheck PASS");
    }
}
