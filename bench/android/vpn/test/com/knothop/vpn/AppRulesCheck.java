package com.knothop.vpn;

import java.io.File;
import java.nio.file.Files;

/** Разбор, валидация, лимит и сохранение правил по приложениям без Android. */
public final class AppRulesCheck {
    private static void check(boolean ok, String why) { if (!ok) throw new AssertionError(why); }
    public static void main(String[] args) throws Exception {
        String hexNode = "ab".repeat(16);

        // parse: пустая и битая строка дают пустой набор
        check(AppRules.parse("").apps.isEmpty(), "empty text gives empty rules");
        check(AppRules.parse("{broken").apps.isEmpty(), "broken JSON gives empty rules");
        check(AppRules.parse("{\"apps\":5}").apps.isEmpty(), "non-object apps gives empty rules");

        // set / валидация имён пакетов и действий
        AppRules r = new AppRules();
        check(r.set("org.example.app", "direct"), "valid direct rule accepted");
        check(r.set("org.example.node", hexNode), "valid node rule accepted");
        check(!r.set("x", "direct"), "single-segment package rejected");
        check(!r.set("a b.c", "direct"), "package with space rejected");
        check(!r.set("", "direct"), "empty package rejected");
        check(!r.set(null, "direct"), "null package rejected");
        check(!r.set("a." + "b".repeat(254), "direct"), "package longer than 255 rejected");
        check(r.set("a." + "b".repeat(253), "direct"), "package of exactly 255 accepted");
        check(!r.set("org.example.app", "DIRECT"), "uppercase action rejected");
        check(!r.set("org.example.app", "exit"), "unknown action rejected");
        check(!r.set("org.example.app", "AB".repeat(16)), "uppercase hex node rejected");
        check(!r.set("org.example.app", "ab".repeat(15)), "short hex node rejected");
        check("direct".equals(r.apps.get("org.example.app")), "rejected action does not overwrite existing rule");

        // parse отбрасывает недопустимые записи
        String dirty = "{\"apps\":{\"x\":\"direct\",\"a b.c\":\"direct\",\"org.ok.app\":\"direct\","
                + "\"org.bad.action\":\"exit\",\"org.bad.hex\":\"" + "AB".repeat(16) + "\",\"org.num\":5}}";
        AppRules parsed = AppRules.parse(dirty);
        check(parsed.apps.size() == 1 && "direct".equals(parsed.apps.get("org.ok.app")), "parse keeps only valid entries");

        // set(pkg, null) снимает правило
        check(r.set("org.example.node", null), "null action removes rule");
        check(!r.apps.containsKey("org.example.node"), "removed rule is gone");
        check(r.set("org.example.node", hexNode) && r.set("org.example.node", null), "re-add then remove");
        check(!r.set("x", null) || !r.apps.containsKey("x"), "invalid package removal does not add entry");

        // directPackages: только direct
        AppRules d = new AppRules();
        d.set("org.direct.one", "direct");
        d.set("org.node.one", hexNode);
        d.set("org.direct.two", "direct");
        java.util.List<String> direct = d.directPackages();
        check(direct.size() == 2 && direct.contains("org.direct.one") && direct.contains("org.direct.two"),
                "directPackages returns only direct packages");
        check(!direct.contains("org.node.one"), "node-bound package is not direct");

        // round-trip: нода сохраняется, но не попадает в direct
        AppRules rt = AppRules.parse(d.toJson());
        check(rt.apps.equals(d.apps), "toJson -> parse round-trip keeps all rules");
        check(hexNode.equals(rt.apps.get("org.node.one")), "node rule survives round-trip");
        check(rt.directPackages().size() == 2, "node rule stays out of directPackages after round-trip");

        // лимит 500
        AppRules full = new AppRules();
        for (int i = 0; i < 500; i++) check(full.set("org.lim.p" + i, "direct"), "entry " + i + " accepted");
        check(full.apps.size() == 500, "500 entries stored");
        check(!full.set("org.lim.extra", "direct"), "501st new entry rejected");
        check(full.set("org.lim.p0", hexNode), "update of existing entry allowed at limit");
        check(hexNode.equals(full.apps.get("org.lim.p0")), "existing entry updated at limit");
        check(full.set("org.lim.p1", null) && full.set("org.lim.extra", "direct"), "slot freed by removal is reusable");
        check(AppRules.parse(full.toJson()).apps.size() == 500, "500 entries survive round-trip");

        // save / load через временный каталог
        File state = Files.createTempDirectory("kh-apprules-").toFile();
        check(AppRules.load(state).apps.isEmpty(), "missing app_rules.json loads as empty");
        check(!AppRules.file(state).exists(), "no app_rules.json before save");
        AppRules s = new AppRules();
        s.set("org.save.direct", "direct");
        s.set("org.save.node", hexNode);
        s.save(state);
        check(AppRules.file(state).isFile(), "save writes app_rules.json");
        check(!new File(state, "app_rules.json.tmp").exists(), "no tmp file after save");
        AppRules loaded = AppRules.load(state);
        check(loaded.apps.equals(s.apps), "load returns saved rules");
        s.set("org.save.direct", null);
        s.save(state);
        check(AppRules.load(state).apps.equals(s.apps) && !AppRules.load(state).apps.containsKey("org.save.direct"),
                "second save replaces file");
        check(!new File(state, "app_rules.json.tmp").exists(), "no tmp file after second save");

        System.out.println("AppRulesCheck PASS");
    }
}
