package com.knothop.vpn;

/** Разбор тега релиза из редиректа GitHub `releases/latest` (без API): только https, github.com и путь нашего репозитория. */
public final class UpdateCheckCheck {
    private static void check(boolean ok, String why) { if (!ok) throw new AssertionError(why); }
    public static void main(String[] args) {
        check("v0.1.98".equals(UpdateCheck.tagFromLocation("https://github.com/msazanov/KnotHop/releases/tag/v0.1.98")), "absolute location");
        check("v0.1.98".equals(UpdateCheck.tagFromLocation("/msazanov/KnotHop/releases/tag/v0.1.98")), "relative location");
        check(UpdateCheck.number(UpdateCheck.tagFromLocation("https://github.com/msazanov/KnotHop/releases/tag/v0.1.98")) == 98, "number from tag");
        for (String bad : new String[]{
                "http://github.com/msazanov/KnotHop/releases/tag/v0.1.98",          // не https
                "https://evil.example/msazanov/KnotHop/releases/tag/v0.1.999",      // чужой хост
                "https://github.com.evil.example/msazanov/KnotHop/releases/tag/v0.1.999",
                "https://github.com/other/KnotHop/releases/tag/v0.1.999",           // чужой репозиторий
                "https://github.com/msazanov/KnotHop/releases",                     // релизов нет: редирект на список
                "https://github.com/msazanov/KnotHop/releases/tag/v0.1.98/extra",
                "https://github.com/msazanov/KnotHop/releases/tag/",
                "null", ""}) {
            check(UpdateCheck.tagFromLocation(bad).isEmpty(), "must reject: " + bad);
        }
        check(UpdateCheck.number("v0.1.x") == 0 && UpdateCheck.number("") == 0 && UpdateCheck.number("v0.1.1234567890") == 0, "bad numbers");
        System.out.println("UpdateCheckCheck PASS");
    }
}
