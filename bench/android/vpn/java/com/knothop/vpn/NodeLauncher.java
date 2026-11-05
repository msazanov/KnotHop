package com.knothop.vpn;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Process;

import java.io.File;

/**
 * Единственные ворота запуска узла. Нативная часть запускается не более одного раза на процесс: после остановки в процессе остаются
 * глобальные приёмники транспортов (mesh, reality), таблицы и соединения. Поэтому повторный запуск узла = перезапуск процесса приложения
 * с отложенным режимом (pending_mode), который MainActivity исполняет в чистом процессе обычным путём.
 */
final class NodeLauncher {
    private NodeLauncher() { }

    /** Нативная часть (client) уже запускалась в этом процессе. Новый процесс начинает с false, так что цикла перезапусков нет. */
    static volatile boolean nativeStarted;
    /** Есть видимый экран приложения: из службы можно открыть активность перезапуска (фоновые запуски Android блокирует). */
    static volatile boolean uiVisible;

    static final String PENDING_MODE = "pending_mode";
    static final String PENDING_TS = "pending_ts";
    private static final long PENDING_TTL_MS = 30_000;
    private static final String CHANNEL = "knothop";

    /** Узел сейчас не работает (нет живой нативной части), но процесс уже запускал её: чистого запуска в этом процессе быть не может. */
    static boolean needsRestart() {
        if (!nativeStarted) return false;
        String p = KnotHopVpnService.phase;
        return !("tun".equals(p) || "connecting".equals(p) || "up".equals(p));
    }

    /**
     * Запустить узел в режиме 1 (сеть) или 2 (VPN). Чистый процесс - обычный запуск службы. Грязный - режим сохраняется и процесс
     * перезапускается; без видимого экрана (служба, уведомление) перезапуск Android может запретить, тогда пользователю
     * показывается «Откройте приложение», а режим исполнит MainActivity при открытии. Возвращает false, если запуска не произошло.
     */
    static boolean start(Context ctx, int mode) {
        if (mode != 1) mode = 2;
        if (!needsRestart()) {
            ctx.startForegroundService(new Intent(ctx, KnotHopVpnService.class).setAction(KnotHopVpnService.A_MODE)
                    .putExtra(KnotHopVpnService.EXTRA_MODE, mode));
            return true;
        }
        savePending(ctx, mode);
        if (ctx instanceof Activity || uiVisible) {
            try {
                restartProcess(ctx);
                return true;
            } catch (Throwable t) {
                Util.log("перезапуск процесса не удался: " + t);
            }
        }
        askOpenApp(ctx);
        return false;
    }

    private static void savePending(Context ctx, int mode) {
        // commit, не apply: следующий шаг убивает процесс
        ctx.getSharedPreferences("p", Context.MODE_PRIVATE).edit().putInt(PENDING_MODE, mode).putLong(PENDING_TS, System.currentTimeMillis()).commit();
    }

    /** Режим, ожидающий после перезапуска (1 или 2), либо 0. Запись стирается до исполнения: повторить её нельзя. */
    static int takePending(SharedPreferences sp) {
        int m = sp.getInt(PENDING_MODE, 0);
        long ts = sp.getLong(PENDING_TS, 0);
        if (sp.contains(PENDING_MODE) || sp.contains(PENDING_TS)) sp.edit().remove(PENDING_MODE).remove(PENDING_TS).commit();
        long age = System.currentTimeMillis() - ts;
        return (m == 1 || m == 2) && age >= 0 && age <= PENDING_TTL_MS ? m : 0;
    }

    private static void restartProcess(Context ctx) {
        Context app = ctx.getApplicationContext();
        // ошибка прошлой сессии не должна всплыть в новом процессе
        try { new File(new File(app.getFilesDir(), "state"), "error.txt").delete(); } catch (Throwable ignored) { }
        app.startActivity(new Intent(app, RestartActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_NO_ANIMATION)
                .putExtra(RestartActivity.EXTRA_PID, Process.myPid()));
        Process.killProcess(Process.myPid());
    }

    private static void askOpenApp(Context ctx) {
        try {
            Context app = ctx.getApplicationContext();
            NotificationManager nm = (NotificationManager) app.getSystemService(Context.NOTIFICATION_SERVICE);
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "KnotHop", NotificationManager.IMPORTANCE_LOW));
            PendingIntent open = PendingIntent.getActivity(app, 3, new Intent(app, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            nm.notify(2, new Notification.Builder(app, CHANNEL).setContentTitle("KnotHop").setContentText("Откройте приложение, чтобы запустить узел")
                    .setSmallIcon(android.R.drawable.ic_lock_lock).setAutoCancel(true).setContentIntent(open).build());
        } catch (Throwable ignored) { }
    }

    /** Имя процесса оканчивается на :restart - там ничего, кроме RestartActivity, не нужно (нативную библиотеку не грузим). */
    static boolean isRestartProcess(Context c) {
        try {
            String name;
            if (android.os.Build.VERSION.SDK_INT >= 28) name = android.app.Application.getProcessName();
            else name = Util.read(new File("/proc/self/cmdline")).trim();
            return name != null && name.endsWith(":restart");
        } catch (Throwable t) {
            return false;
        }
    }
}
