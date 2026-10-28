package com.knothop.vpn;

import java.io.File;
import java.nio.file.Files;

/** Начальные правила и изолированный импорт в контексте конкретной ноды. */
public final class RoutingNodeCheck {
    private static void check(boolean ok, String why) { if (!ok) throw new AssertionError(why); }
    public static void main(String[] args) throws Exception {
        String a = "11".repeat(16), b = "22".repeat(16);
        File state = Files.createTempDirectory("kh-default-routing-").toFile();
        check(RoutingCfg.ensureDefaults(state), "first setup writes defaults");
        RoutingCfg defaults = RoutingCfg.load(state);
        check(defaults.mode.equals("rules") && defaults.rules.size() == 4 && defaults.manual.size() == 4, "LAN and Russia preset");
        check(defaults.rules.stream().allMatch(r -> r.action.equals("direct")), "only explicit direct defaults");
        defaults.manual.add(new RoutingCfg.Manual("example.org", "exit:"+a)); defaults.save(state);
        String before = Files.readString(RoutingCfg.file(state).toPath());
        check(!RoutingCfg.ensureDefaults(state) && before.equals(Files.readString(RoutingCfg.file(state).toPath())), "never overwrite user settings");
        Files.writeString(RoutingCfg.file(state).toPath(), "{broken");
        check(!RoutingCfg.ensureDefaults(state) && Files.readString(RoutingCfg.file(state).toPath()).equals("{broken"), "never overwrite corrupt user work");
        RoutingImport.Result raw = RoutingImport.parse("[{\"outboundTag\":\"proxy\",\"domain\":[\"geosite:youtube\",\"example.org\"]},{\"outboundTag\":\"direct\",\"ip\":[\"geoip:ru\"]}]");
        RoutingImport.Result scoped = RoutingImport.forTarget(raw,a);
        check(scoped.count()==2 && scoped.skipped.size()==1, "direct stays in global settings");
        check(raw.rules.get(0).action.equals("default"), "projection does not modify parsed source");
        RoutingCfg c = new RoutingCfg(); c.rules.add(new RoutingCfg.Rule("geoip","ru","direct"));
        c.manual.add(new RoutingCfg.Manual("other.example","exit:"+b));
        check(RoutingImport.apply(c,scoped)==2, "attach JSON lists to the selected node");
        check(c.rules.get(0).action.equals("direct") && c.manual.get(0).action.equals("exit:"+b), "other rules survive");
        check(c.rules.get(1).action.equals("exit:"+a), "new category targets node A");
        check(RoutingImport.forTarget(scoped,a).count()==2, "already scoped internal import is retained");
        check(RoutingImport.conflicts(c,RoutingImport.forTarget(raw,b))==2, "reassignment is reported before saving");
        System.out.println("RoutingNodeCheck PASS");
    }
}
