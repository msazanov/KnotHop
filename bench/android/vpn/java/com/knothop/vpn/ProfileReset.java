package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.widget.Toast;

import java.io.File;

/**
 * «Забыть профиль» (решение владельца 04.11): стирается ВСЁ состояние телефона — ключ (identity), таблица прав и контакты, приглашения,
 * очереди LXMF. Остаётся только имя телефона. Следующий запуск приложения создаёт новую identity (главный экран открывается сразу):
 * телефон начинает с чистого листа, управляемые им ноды остаются без этого админа.
 * Кнопка живёт в настройках своей ноды (долгое нажатие на свой телефон на графе).
 */
final class ProfileReset {
    private static final java.util.concurrent.atomic.AtomicBoolean busy = new java.util.concurrent.atomic.AtomicBoolean();
    private ProfileReset() { }

    /** Подтверждение; после сброса настройки ноды закрываются и показывается главный экран. */
    static void confirm(Activity a) {
        new AlertDialog.Builder(a).setTitle("Забыть профиль?")
                .setMessage("Будет стёрто всё: ключ телефона, ваша собственная сеть и её записи, приглашения и коды серверов, чужие сети. VPN остановится, "
                        + "при следующем запуске телефон получит новый ключ.\n\nЕсли этот телефон — админ сети, серверы, вступившие по его кодам, "
                        + "останутся без админа: их придётся развернуть заново новым кодом. Отменить нельзя.")
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Забыть", (d, w) -> run(a))
                .show();
    }

    /** Удалить всё в каталоге состояния, кроме имени телефона. Ссылки не разыменовываются (удаляется сама ссылка). */
    private static void wipe(File st) throws java.io.IOException {
        File[] fs = st.listFiles();
        if (fs == null) return;
        for (File f : fs) {
            if ("node-name.txt".equals(f.getName())) continue;
            del(f.toPath());
        }
        String[] left = st.list();
        if (left != null && left.length > (new File(st, "node-name.txt").exists() ? 1 : 0)) throw new java.io.IOException("не всё состояние удалось стереть");
    }

    private static void del(java.nio.file.Path p) throws java.io.IOException {
        if (java.nio.file.Files.isDirectory(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            try (java.nio.file.DirectoryStream<java.nio.file.Path> ds = java.nio.file.Files.newDirectoryStream(p)) {
                for (java.nio.file.Path c : ds) del(c);
            }
        }
        java.nio.file.Files.deleteIfExists(p);
    }

    private static void run(Activity a) {
        if (!busy.compareAndSet(false, true)) return;
        Context app = a.getApplicationContext();
        app.startService(new Intent(app, KnotHopVpnService.class).setAction(KnotHopVpnService.A_STOP));
        new Thread(() -> {
            File st = new File(app.getFilesDir(), "state");
            String err = "";
            try {
                // Остановка с нативным watchdog может занимать до 6 с. Не менять Trust живого узла.
                for (int i = 0; i < 100 && (!"idle".equals(KnotHopVpnService.phase) || KnotHopVpnService.tunHeld); i++) Thread.sleep(100);
                if (!"idle".equals(KnotHopVpnService.phase) || KnotHopVpnService.tunHeld) throw new IllegalStateException("Узел ещё останавливается; повторите позже");
                new File(st, "status.json").delete(); // только после остановки: CLI проверяет свежесть статуса
                wipe(st);
                app.getSharedPreferences("p", Context.MODE_PRIVATE).edit().remove("profile").remove("name_asked").apply();   // "profile" - остаток прежней схемы
            } catch (Exception ex) {
                err = ex.getMessage();
            } finally {
                busy.set(false);
            }
            final String e = err;
            a.runOnUiThread(() -> {
                if (!e.isEmpty()) { Toast.makeText(app, e, Toast.LENGTH_LONG).show(); return; }
                a.startActivity(new Intent(app, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP));
                a.finish();
            });
        }, "knothop-forget").start();
    }
}
