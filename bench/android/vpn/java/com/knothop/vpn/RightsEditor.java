package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.File;
import java.util.function.Consumer;

/**
 * Изменение прав участника своей сети: диалог USE..CONFIG, подтверждение и «rights-set». Общий для «Моей ноды» и списка
 * пользователей на главном экране. Backend сам подписывает запись (выдать можно только подмножество своих прав) и кладёт её
 * в inbox13; подтверждения применения на других нодах нет, поэтому итог - только «в очереди». HOST_ACCESS здесь не меняется.
 */
final class RightsEditor {
    static final int USE = 1, TRANSIT = 2, EXIT = 4, ADD = 8, REMOVE = 16, CONFIG = 32, ALL = 63;
    static final int[] BITS = {USE, TRANSIT, EXIT, ADD, REMOVE, CONFIG};
    static final String[] NAMES = {"USE", "TRANSIT", "EXIT", "ADD", "REMOVE", "CONFIG"};
    static final String[] HINTS = {"использовать выходы сети", "быть транзитом", "быть выходом в интернет", "добавлять участников", "отзывать права", "настраивать сеть"};

    private RightsEditor() { }

    static String rightsText(int mask) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < BITS.length; i++) if ((mask & BITS[i]) != 0) b.append(b.length() == 0 ? "" : ", ").append(NAMES[i]);
        return b.length() == 0 ? "нет" : b.toString();
    }

    static String clip(String s) {
        String v = s == null ? "" : s.replaceAll("[\\p{Cntrl}]", " ");
        return v.length() > 120 ? v.substring(0, 120) + "…" : v;
    }

    /** Чекбоксы USE..CONFIG; те, что у меня самого нет (grantable), недоступны. {@code view} - ответ trust-view. */
    static void edit(Activity a, JSONObject view, File state, String holder, String name, int current, Consumer<String> notice, Runnable done) {
        if (view == null) return;
        int grantable = view.optInt("grantable", 0) & ALL;
        LinearLayout col = new LinearLayout(a);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(48, 16, 48, 0);
        CheckBox[] boxes = new CheckBox[BITS.length];
        for (int i = 0; i < BITS.length; i++) {
            CheckBox c = new CheckBox(a);
            c.setText(NAMES[i] + " — " + HINTS[i]);
            c.setChecked((current & BITS[i]) != 0);
            c.setEnabled((grantable & BITS[i]) != 0);
            boxes[i] = c;
            col.addView(c);
        }
        new AlertDialog.Builder(a).setTitle("Права: " + (name == null ? NodeAdminActivity.brief(holder) : name))
                .setView(col).setNegativeButton("Отмена", null)
                .setPositiveButton("Далее", (d, w) -> {
                    int next = 0;
                    for (int i = 0; i < BITS.length; i++) if (boxes[i].isChecked()) next |= BITS[i];
                    if (next == current) { Toast.makeText(a, "Права не изменились", Toast.LENGTH_SHORT).show(); return; }
                    confirm(a, view, state, holder, name, current, next, notice, done);
                }).show();
    }

    private static void confirm(Activity a, JSONObject view, File state, String holder, String name, int current, int next, Consumer<String> notice, Runnable done) {
        int grantable = view.optInt("grantable", 0) & ALL;
        boolean revokeAll = next == 0;
        // как в Trust::issue: пустые права (отзыв) требуют REMOVE, любые другие - ADD и подмножество своих прав
        if (revokeAll && !view.optBoolean("can_remove", false)) { notice.accept("Нет права REMOVE: снять все права нельзя."); return; }
        if (!revokeAll && !view.optBoolean("can_add", false)) { notice.accept("Нет права ADD: менять права нельзя."); return; }
        if ((next & ~grantable) != 0) { notice.accept("Нельзя выдать права, которых нет у вас."); return; }
        StringBuilder m = new StringBuilder();
        m.append("Участник: ").append(name == null ? "" : name + " ").append(NodeAdminActivity.brief(holder));
        m.append("\nБыло: ").append(rightsText(current)).append("\nСтанет: ").append(revokeAll ? "ничего (все права снимаются)" : rightsText(next));
        if ((next & USE) == 0 && !revokeAll) m.append("\n\nБез USE участник пропадёт из сети.");
        if ((next & ~current & (ADD | REMOVE | CONFIG)) != 0) m.append("\n\nВы выдаёте административные права: участник сможет сам менять права других.");
        m.append("\n\nЗапись подписывается этим телефоном и уходит в очередь; применение на других нодах не подтверждается.");
        new AlertDialog.Builder(a).setTitle(revokeAll ? "Снять все права?" : "Изменить права?").setMessage(m.toString())
                .setNegativeButton("Назад", null)
                .setPositiveButton("Подтвердить", (d, w) -> submit(a, state, holder, next, notice, done)).show();
    }

    private static void submit(Activity a, File state, String holder, int rights, Consumer<String> notice, Runnable done) {
        if (!holder.matches("[0-9a-f]{32}") || (rights & ~ALL) != 0) return;
        new Thread(() -> {
            String msg;
            try {
                String raw = Native.runCLI("rights-set --state " + state.getAbsolutePath() + " --holder " + holder + " --rights " + rights, state.getAbsolutePath());
                if (raw == null || raw.length() > 8192) throw new Exception("bad response");
                JSONObject r = new JSONObject(raw);
                msg = r.optBoolean("accepted", false)
                        ? "Запись подписана и поставлена в очередь; удалённое применение не подтверждено."
                        : "Не принято: " + clip(r.optString("detail", r.optString("rejected", "ошибка backend")));
            } catch (Throwable e) { msg = "Backend не подтвердил запрос (" + e.getClass().getSimpleName() + "). Не считайте его отправленным."; }
            final String shown = msg;
            a.runOnUiThread(() -> {
                if (a.isFinishing() || a.isDestroyed()) return;
                notice.accept(shown);
                if (done != null) done.run();
            });
        }, "knothop-rights-set").start();
    }
}
