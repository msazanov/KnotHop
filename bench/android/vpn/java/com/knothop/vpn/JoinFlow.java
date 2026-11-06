package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.view.WindowManager;
import android.widget.Toast;

import org.json.JSONObject;

/**
 * Вступление по приглашению (ADR 0028 §2.4): разбор строки, диалог с хешами нод и передача ядру команды {@code join}. Один путь для экрана
 * «Вступить», ссылки {@code knothop://i/...} и QR. Новая строка ДОБАВЛЯЕТСЯ к незавершённой стопке (повтор той же строки ничего не
 * добавляет); работающая нода начинает гасить пары сразу, без перезапуска и без обрыва текущих соединений; при выключенной «Сети» пары
 * ждут в приватном pending-invite.json до включения. Строка нигде не хранится в приложении: пины живут в ядре (0600).
 */
final class JoinFlow {
    private JoinFlow() { }

    interface Done { void done(boolean joined); }

    /** Первые 16 hex хеша, группами по 4 - для сверки глазами. */
    static String fp(String h) {
        return h.length() < 16 ? h : h.substring(0, 4) + " " + h.substring(4, 8) + " " + h.substring(8, 12) + " " + h.substring(12, 16);
    }

    static boolean nodeActive() {
        String p = KnotHopVpnService.phase;
        return !"idle".equals(p) && !"error".equals(p);
    }

    /** Текст диалога подтверждения: число нод и их хеши (сверить с теми, что назвал приглашающий). */
    static String confirmText(Profile pr) {
        StringBuilder m = new StringBuilder("Телефон попросит ").append(pr.nodeCount).append(pr.nodeCount == 1 ? " ноду" : " нод(ы)")
                .append(" принять его в сеть. Пин каждой ноды знает только она; приглашение одноразовое.\n\nХеши нод (сверьте с теми, что назвал приглашающий):\n");
        for (int i = 0; i < pr.nodeCount; i++) m.append("  ").append(fp(pr.nodeHash(i))).append('\n');
        m.append("\nПрава вам назначит каждая нода при погашении. Вступление никому не даёт управления этим телефоном.");
        return m.toString().trim();
    }

    /** Разобрать строку, показать диалог с хешами и, если пользователь согласен, вступить. Ошибка разбора - сообщение, не исключение. */
    static void confirmAndJoin(Activity a, String text, Done done) {
        final Profile pr;
        try {
            pr = Profile.parse(text);
        } catch (Throwable e) {
            Toast.makeText(a, "Не удалось: " + e.getMessage(), Toast.LENGTH_LONG).show();
            if (done != null) done.done(false);
            return;
        }
        AlertDialog d = new AlertDialog.Builder(a).setTitle("Вступить в сеть?").setMessage(confirmText(pr))
                .setNegativeButton("Отмена", (x, w) -> { if (done != null) done.done(false); })
                .setOnCancelListener(x -> { if (done != null) done.done(false); })
                .setPositiveButton("Вступить", (x, w) -> join(a, pr, done)).show();
        d.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        d.getButton(DialogInterface.BUTTON_POSITIVE).setFilterTouchesWhenObscured(true);   // F8
    }

    /** Без диалога (лабораторный интент); в обычной сборке не вызывается. */
    static void joinNow(Activity a, String text) {
        try { join(a, Profile.parse(text), null); } catch (Throwable e) { Util.lab("JOIN FAIL " + e); }
    }

    private static void join(Activity a, Profile pr, Done done) {
        new Thread(() -> {
            // ключ создаётся при запуске приложения; здесь страховка на случай гонки с первым запуском (идемпотентно)
            Ctl.call(a, Ctl.req("init"));
            JSONObject r;
            try { r = Ctl.call(a, Ctl.req("join").put("invite", pr.raw)); } catch (Exception e) { r = new JSONObject(); }
            final JSONObject res = r;
            a.runOnUiThread(() -> {
                if (a.isFinishing() || a.isDestroyed()) return;
                if (!res.optBoolean("ok")) {
                    Util.lab("JOIN FAIL " + res.optString("error"));
                    new AlertDialog.Builder(a).setTitle("Не удалось вступить").setMessage(res.optString("error", "неизвестная ошибка")).setPositiveButton("OK", null).show();
                    if (done != null) done.done(false);
                    return;
                }
                int added = res.optInt("added", 1);
                String msg = added == 0 ? "Это приглашение уже принято: ждём ответа нод."
                        : "Приглашение принято к исполнению: нод " + added + ".";
                if (!nodeActive()) msg += " Включите «Сеть» внизу: телефон свяжется с нодами и погасит приглашение.";
                Toast.makeText(a, msg, Toast.LENGTH_LONG).show();
                if (done != null) done.done(true);
            });
        }, "knothop-join").start();
    }
}
