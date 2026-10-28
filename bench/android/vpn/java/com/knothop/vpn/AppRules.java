package com.knothop.vpn;

import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Правила по приложениям на ЭТОМ телефоне: пакет -> "direct" (мимо VPN) или 32-hex нода (трафик приложения через эту ноду).
 * «Мимо VPN» исполняет система (Builder.addDisallowedApplication), поэтому работает и на Android 12; назначение на ноду исполняется
 * только после того, как нативная часть сможет определять владельца потока, до тех пор такие записи хранятся и не применяются.
 */
final class AppRules {
    static final String DIRECT = "direct";
    private static final Pattern PKG = Pattern.compile("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+");
    private static final int MAX = 500;

    final Map<String, String> apps = new LinkedHashMap<>();

    static File file(File state) { return new File(state, "app_rules.json"); }

    static boolean validPackage(String p) { return p != null && p.length() <= 255 && PKG.matcher(p).matches(); }

    static boolean validAction(String a) { return DIRECT.equals(a) || (a != null && a.matches("[0-9a-f]{32}")); }

    static AppRules load(File state) {
        return parse(Util.read(file(state)));
    }

    static AppRules parse(String text) {
        AppRules r = new AppRules();
        try {
            JSONObject o = new JSONObject(text).optJSONObject("apps");
            if (o == null) return r;
            for (Iterator<String> it = o.keys(); it.hasNext() && r.apps.size() < MAX; ) {
                String p = it.next();
                String a = o.optString(p);
                if (validPackage(p) && validAction(a)) r.apps.put(p, a);
            }
        } catch (Throwable ignored) { }
        return r;
    }

    String toJson() {
        try {
            JSONObject apps = new JSONObject();
            for (Map.Entry<String, String> e : this.apps.entrySet()) apps.put(e.getKey(), e.getValue());
            return new JSONObject().put("apps", apps).toString();
        } catch (Exception e) { return "{\"apps\":{}}"; }
    }

    void save(File state) throws Exception {
        state.mkdirs();
        File tmp = new File(state, "app_rules.json.tmp");
        Files.write(tmp.toPath(), toJson().getBytes(StandardCharsets.UTF_8));
        Files.move(tmp.toPath(), file(state).toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    /** Установить или снять (action == null) правило; false, если запись недопустима или список полон. */
    boolean set(String pkg, String action) {
        if (!validPackage(pkg)) return false;
        if (action == null) { apps.remove(pkg); return true; }
        if (!validAction(action) || (!apps.containsKey(pkg) && apps.size() >= MAX)) return false;
        apps.put(pkg, action);
        return true;
    }

    /** Пакеты, которые система должна пустить мимо туннеля. */
    java.util.List<String> directPackages() {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (Map.Entry<String, String> e : apps.entrySet()) if (DIRECT.equals(e.getValue())) out.add(e.getKey());
        return out;
    }
}
