package com.knothop.vpn;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

final class Util {
    /** Лабораторная сборка (build.sh с KNOTHOP_LAB=1 меняет значение): управление по интентам и подробные логи. В обычной сборке выключено. */
    static final boolean LAB_BUILD = false;

    static void lab(String msg) {
        if (LAB_BUILD) android.util.Log.i("knothopui", msg);
    }

    /**
     * Расширенный журнал (флажок debug в приложении). Только больше строк журнала: лабораторные интенты, права и допуск от него не зависят.
     * Журнал приложения лежит в приватном каталоге (не в logcat) и не содержит профиля, ключей, приглашений и pin; наружу уходит только
     * по действию пользователя («Поделиться журналом»).
     */
    static volatile boolean debug;
    private static final long DBG_MAX = 256 * 1024;
    private static File dbgFile;

    /** Читает флажок из настроек и передаёт его нативной части. Вызывается при старте процесса. */
    static synchronized void init(android.content.Context c) {
        dbgFile = new File(c.getFilesDir(), "ui-log.txt");
        setDebug(c.getSharedPreferences("p", android.content.Context.MODE_PRIVATE).getBoolean("debug", false));
    }

    static void setDebug(boolean on) {
        debug = on;
        try { Native.setDebug(on); } catch (Throwable ignored) { }   // нативной библиотеки ещё может не быть
        if (on) dbg("отладка включена, версия приложения в журнале: " + android.os.Build.VERSION.SDK_INT + " " + android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL);
    }

    /** Строка в журнал приложения (формат как у нативного: «[мс] текст»), только при включённой отладке; файл ограничен по размеру. */
    static void dbg(String msg) {
        if (debug) log(msg);
    }

    /** Строка в журнал приложения независимо от отладки: сообщения, которых больше нет на главном экране (версия, геоданные, права, обновление). */
    static synchronized void log(String msg) {
        if (dbgFile == null) return;
        try {
            if (dbgFile.length() > DBG_MAX) {
                File old = new File(dbgFile.getPath() + ".1");
                old.delete();
                dbgFile.renameTo(old);
            }
            try (java.io.FileOutputStream o = new java.io.FileOutputStream(dbgFile, true)) {
                o.write(("[" + System.currentTimeMillis() + "] ui: " + msg.replace('\n', ' ') + "\n").getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) { }
    }

    /** События службы: в logcat только в лабораторной сборке, в журнал приложения - при включённой отладке. */
    static void svc(String msg) {
        lab(msg);
        dbg(msg);
    }

    /** Журнал нативной части и журнал приложения одним списком по времени ([мс] в начале строки; строка без метки идёт за предыдущей). */
    static String[] mergedLog(String nativeLog) {
        if (dbgFile == null) return nativeLog.split("\n");
        String ui = read(dbgFile);
        if (ui.isEmpty()) return nativeLog.split("\n");
        java.util.List<long[]> idx = new java.util.ArrayList<>();
        java.util.List<String> all = new java.util.ArrayList<>();
        for (String src : new String[]{nativeLog, ui}) {
            long ts = 0;
            for (String ln : src.split("\n")) {
                if (ln.length() > 3 && ln.charAt(0) == '[') {
                    int e = ln.indexOf(']');
                    if (e > 1 && e < 16) { try { ts = Long.parseLong(ln.substring(1, e)); } catch (NumberFormatException ignored) { } }
                }
                idx.add(new long[]{ts, all.size()});
                all.add(ln);
            }
        }
        idx.sort((a, b) -> a[0] != b[0] ? Long.compare(a[0], b[0]) : Long.compare(a[1], b[1]));
        String[] out = new String[all.size()];
        for (int i = 0; i < out.length; i++) out[i] = all.get((int) idx.get(i)[1]);
        return out;
    }

    /** Единственное, что зашито в приложении (модель 0013): публичные узлы RNS для анонсов и первого Link. Данные через них не идут. Источник: deploy-pilot/public_rns.txt (rns_ok=True). */
    static final String PUBLIC_RNS = "catz.rns.moscow:4242\n46.188.15.32:4242\n185.9.77.240:4242\n217.70.19.114:4242\n";

    static final int MTU = 1327;

    static String read(File f) {
        try {
            return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}
