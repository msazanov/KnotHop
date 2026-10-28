package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.widget.Toast;

import java.io.File;

/**
 * «Забыть профиль» (R-2, R-3): профиль, приглашение, зачисление и чужие корни доверия. Идентичность телефона и записи его
 * собственной сети остаются. Чужие якоря стирает нативная часть (`forget-network`) после остановки службы.
 * Кнопка живёт в настройках своей ноды (долгое нажатие на свой телефон на графе).
 */
final class ProfileReset {
    private static final java.util.concurrent.atomic.AtomicBoolean busy = new java.util.concurrent.atomic.AtomicBoolean();
    private ProfileReset() { }

    /** Подтверждение; после сброса настройки ноды закрываются и показывается главный экран. */
    static void confirm(Activity a) {
        new AlertDialog.Builder(a).setTitle("Забыть профиль?")
                .setMessage("Профиль, приглашение и чужие сети будут стёрты, VPN остановится. Ключ телефона и ваша собственная сеть сохранятся.")
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Забыть", (d, w) -> run(a))
                .show();
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
                if (new File(st, "identity.key").exists()) {
                    String sd = st.getAbsolutePath();
                    if (Native.runVpn("forget-network --state " + sd, sd) != 0) throw new IllegalStateException("Не удалось забыть чужие сети: " + Util.read(new File(st, "error.txt")));
                }
                for (String n : new String[]{"profile.txt", "enrollment.json", "enroll-consent.json", "enroll-consented.json", "enroll-join.json"}) new File(st, n).delete();
                app.getSharedPreferences("p", Context.MODE_PRIVATE).edit().remove("profile").apply();
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
