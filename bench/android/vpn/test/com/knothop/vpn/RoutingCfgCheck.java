package com.knothop.vpn;

import org.json.JSONObject;

import java.io.File;
import java.nio.file.Files;

/**
 * Проверка модели RoutingCfg на JVM (без Android): java -cp out:json.jar com.knothop.vpn.RoutingCfgCheck.
 * Нужен org.json (в android.jar только заглушки). В APK не входит: build.sh компилирует только каталог java/.
 */
public final class RoutingCfgCheck {
    private static int fails;

    private static void check(boolean ok, String what) {
        if (!ok) { fails++; System.out.println("FAIL: " + what); }
    }

    public static void main(String[] args) throws Exception {
        File dir = Files.createTempDirectory("routingcfg").toFile();
        String d1 = "0123456789abcdef0123456789abcdef", d2 = "fedcba9876543210fedcba9876543210";

        // старый файл: режим priority + рейтинг + неизвестное поле
        String old = "{\"mode\":\"priority\",\"priority\":[\"" + d1 + "\",\"" + d2 + "\"],\"future\":{\"x\":1},"
                + "\"rules\":[{\"t\":\"geoip\",\"n\":\"ru\",\"a\":\"direct\"},{\"t\":\"geosite\",\"n\":\"youtube\",\"a\":\"exit:" + d1 + "\"}],"
                + "\"manual\":[{\"v\":\"example.org\",\"a\":\"default\"}]}";
        RoutingCfg c = RoutingCfg.parse(old);
        check(!c.corrupt, "old parses");
        check(c.mode.equals("auto"), "priority mode reads as auto");
        check(c.hadLegacy, "legacy detected");
        check(c.rules.size() == 2 && c.manual.size() == 1, "old entries kept");

        Files.write(RoutingCfg.file(dir).toPath(), old.getBytes("UTF-8"));
        check(RoutingCfg.migrateLegacy(dir), "migration rewrites file");
        JSONObject m = new JSONObject(new String(Files.readAllBytes(RoutingCfg.file(dir).toPath()), "UTF-8"));
        check(m.getJSONArray("priority").length() == 0, "priority cleared");
        check(m.getString("mode").equals("auto"), "mode auto after migration");
        check(m.getJSONArray("ui_legacy").getJSONObject(0).getJSONArray("priority").length() == 2, "backup holds old priority");
        check(!m.getJSONArray("ui_legacy").getJSONObject(0).getBoolean("ack"), "backup not acked");
        check(m.getJSONObject("future").getInt("x") == 1, "unknown key kept");
        check(m.getJSONArray("rules").length() == 2, "rules kept");
        check(!RoutingCfg.migrateLegacy(dir), "migration is one-shot");

        // подтверждение и повторное сохранение не теряют резервную копию
        RoutingCfg c2 = RoutingCfg.load(dir);
        check(c2.unackedLegacy() != null && c2.legacyCount(c2.unackedLegacy()) == 2, "unacked legacy visible");
        c2.ackLegacy();
        check(c2.save(dir).isEmpty(), "save after ack");
        RoutingCfg c3 = RoutingCfg.load(dir);
        check(c3.unackedLegacy() == null, "ack persisted");
        check(c3.rest().has("ui_legacy"), "backup survives save");

        // выключенные записи: туда и обратно, порядок сохраняется, Rust их не видит
        RoutingCfg c4 = new RoutingCfg();
        c4.mode = "rules";
        c4.rules.add(new RoutingCfg.Rule("geoip", "ru", "direct"));
        c4.rules.add(new RoutingCfg.Rule("geosite", "youtube", "default"));
        c4.rules.add(new RoutingCfg.Rule("geosite", "google", "default"));
        c4.rules.get(1).enabled = false;
        c4.manual.add(new RoutingCfg.Manual("a.example", "default"));
        c4.manual.add(new RoutingCfg.Manual("10.0.0.0/8", "direct"));
        c4.manual.get(0).enabled = false;
        check(c4.save(dir).isEmpty(), "save with disabled");
        JSONObject j = new JSONObject(new String(Files.readAllBytes(RoutingCfg.file(dir).toPath()), "UTF-8"));
        check(j.getJSONArray("rules").length() == 2, "native sees only enabled rules");
        check(j.getJSONArray("manual").length() == 1, "native sees only enabled manual");
        check(j.getJSONArray("priority").length() == 0, "priority empty on save");
        RoutingCfg c5 = RoutingCfg.load(dir);
        check(c5.rules.size() == 3 && !c5.rules.get(1).enabled && c5.rules.get(1).name.equals("youtube"), "disabled rule back in place");
        check(c5.manual.size() == 2 && !c5.manual.get(0).enabled && c5.manual.get(0).value.equals("a.example"), "disabled manual back in place");
        check(c5.directSig().contains("geoip:ru") && c5.directSig().contains("10.0.0.0/8"), "directSig counts enabled direct");
        c5.manual.get(1).enabled = false;
        c5.rules.get(0).enabled = false;
        check(c5.directSig().isEmpty(), "directSig ignores disabled");

        // повреждённый файл
        check(RoutingCfg.parse("{oops").corrupt, "corrupt detected");
        check(!RoutingCfg.parse("").corrupt, "empty is default");

        // ввод
        check(RoutingCfg.isIp("1.2.3.4") && RoutingCfg.isIp("10.0.0.0/8"), "ip ok");
        check(!RoutingCfg.isIp("256.1.1.1") && !RoutingCfg.isIp("1.2.3.4/33") && !RoutingCfg.isIp("1.2.3"), "ip bad");
        check("example.org".equals(RoutingCfg.cleanManual(" example.org ")), "domain ok");
        check("domain:example.org".equals(RoutingCfg.cleanManual("domain:example.org")), "prefix ok");
        check(RoutingCfg.cleanManual("regexp:.*") == null, "unknown prefix rejected");
        check(RoutingCfg.cleanManual("bad host!") == null, "bad chars rejected");
        check(RoutingCfg.cleanManual("") == null, "empty rejected");

        System.out.println(fails == 0 ? "OK" : fails + " failures");
        System.exit(fails == 0 ? 0 : 1);
    }
}
