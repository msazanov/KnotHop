package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * «Моя нода»: открывается тапом по своему телефону на графе. Кто я, мои права в моей сети и (для админа своего корня)
 * права участников. Данные - из локального Trust через Native.runCLI("trust-view"); изменение - "rights-set": backend сам подписывает
 * запись (выдать можно только подмножество своих прав), кладёт её в inbox13, дальше клиент принимает её локально и шлёт T_REC на
 * текущий выход. Подтверждения применения на других нодах нет, поэтому экран говорит только «в очереди» / «сохранено у меня».
 * HOST_ACCESS здесь не меняется: он выдаётся на экране конкретной ноды.
 */
public final class MyNodeActivity extends Activity {
    private static final int USE = 1, TRANSIT = 2, EXIT = 4, ADD = 8, REMOVE = 16, CONFIG = 32, ALL = 63;
    private static final int[] BITS = {USE, TRANSIT, EXIT, ADD, REMOVE, CONFIG};
    private static final String[] NAMES = {"USE", "TRANSIT", "EXIT", "ADD", "REMOVE", "CONFIG"};
    private static final String[] HINTS = {"использовать выходы сети", "быть транзитом", "быть выходом в интернет", "добавлять участников", "отзывать права", "настраивать сеть"};
    private static final int GREY = 0xFF777777;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private File state;
    private LinearLayout box;
    private JSONObject view;
    private String lastKey = "", notice = "";
    private boolean busy, resumed;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        state = new File(getFilesDir(), "state");
        ScrollView scroll = new ScrollView(this);
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(24, 48, 24, 48);
        scroll.addView(box);
        setContentView(scroll);
    }

    @Override protected void onResume() { super.onResume(); resumed = true; ui.post(tick); }
    @Override protected void onPause() { resumed = false; ui.removeCallbacks(tick); super.onPause(); }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            refresh();
            if (resumed) ui.postDelayed(this, 4000);
        }
    };

    private void refresh() {
        if (busy) return;
        busy = true;
        new Thread(() -> {
            JSONObject got = null;
            try {
                String raw = Native.runCLI("trust-view --state " + state.getAbsolutePath(), state.getAbsolutePath());
                if (raw != null && raw.length() <= 65536) {
                    JSONObject j = new JSONObject(raw);
                    if (!j.has("error")) got = j;
                }
            } catch (Throwable ignored) { }
            final JSONObject result = got;
            runOnUiThread(() -> {
                busy = false;
                if (isFinishing() || isDestroyed()) return;
                String key = String.valueOf(result) + notice + names().toString();
                if (key.equals(lastKey)) return;
                lastKey = key;
                view = result;
                render();
            });
        }, "knothop-mynode-view").start();
    }

    private void render() {
        box.removeAllViews();
        box.addView(NodeTabs.bar(this, NodeTabs.RIGHTS));
        text("Моя нода", 22, true, 0);
        if (view == null) {
            text("Локальное состояние доверия недоступно: приложение ещё не создало identity или не запускалось.", 14, false, GREY);
            return;
        }
        String me = view.optString("me", "");
        String own = NodeName.get(getFilesDir());
        text("Имя: " + (own.isEmpty() ? "телефон-" + (me.length() >= 6 ? me.substring(0, 6) : me) : own), 15, true, 0);
        Button rename = new Button(this);
        rename.setAllCaps(false);
        rename.setText("Изменить имя");
        rename.setOnClickListener(v -> NodeName.dialog(this, getFilesDir(), () -> { lastKey = ""; refresh(); }));
        box.addView(rename);
        text("Узлы сети узнают новое имя при следующем подключении телефона к выходу.", 12, false, GREY);
        fingerprint(me);
        int mine = view.optInt("my_rights", 0);
        boolean canAdd = view.optBoolean("can_add", false), canRemove = view.optBoolean("can_remove", false);
        text("\nМои права в моей сети", 16, true, 0);
        text(rightsText(mine), 14, false, 0);
        if (!notice.isEmpty()) text(notice, 13, false, 0xFF2E9E4F);
        int queued = view.optInt("queued", 0);
        if (queued > 0) text("В очереди на применение: " + queued + ". Её разбирает работающий клиент (VPN включён), примерно раз в 4 секунды.", 12, false, 0xFFB36B00);

        JSONArray participants = view.optJSONArray("participants");
        if (!(canAdd || canRemove)) {
            text("Вы не администратор своей сети: права участников здесь только просматриваются.", 13, false, GREY);
        } else {
            int n = participants == null ? 0 : participants.length();
            text("\nУчастники моей сети (" + n + ")", 17, true, 0);
            text("Изменение подписывается этим телефоном и уходит на текущий выход; выдать можно только то, что есть у вас ("
                    + rightsText(view.optInt("grantable", 0)) + "). Применение на других нодах не подтверждается.", 12, false, GREY);
            Map<String, String> names = names();
            for (int i = 0; participants != null && i < participants.length(); i++) {
                JSONObject p = participants.optJSONObject(i);
                if (p != null) participant(p, names.get(p.optString("holder", "")), canAdd, canRemove);
            }
            if (n == 0) text("Участников пока нет: выпустите приглашение на главном экране.", 13, false, GREY);
        }

        JSONArray nets = view.optJSONArray("networks");
        if (nets != null && nets.length() > 0) {
            text("\nДругие сети, где я участник (только просмотр)", 16, true, 0);
            for (int i = 0; i < nets.length(); i++) {
                JSONObject o = nets.optJSONObject(i);
                if (o != null) text("Сеть " + o.optString("tag", "?") + ": " + rightsText(o.optInt("rights", 0)), 13, false, 0);
            }
        }
        text("\nПрофиль", 16, true, 0);
        Button forget = new Button(this);
        forget.setAllCaps(false);
        forget.setText("Забыть профиль");
        forget.setOnClickListener(v -> ProfileReset.confirm(this));
        box.addView(forget);
    }

    private void fingerprint(String me) {
        if (!me.matches("[0-9a-f]{32}")) return;
        TextView t = new TextView(this);
        t.setText("Fingerprint (публичный, 32 hex):\n" + me);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextSize(12);
        t.setTextIsSelectable(true);
        t.setPadding(0, 8, 0, 8);
        box.addView(t);
        Button copy = new Button(this);
        copy.setText("Скопировать fingerprint");
        copy.setAllCaps(false);
        copy.setFilterTouchesWhenObscured(true);
        copy.setOnClickListener(v -> {
            ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cb == null) return;
            cb.setPrimaryClip(ClipData.newPlainText("KnotHop fingerprint", me));
            Toast.makeText(this, "Fingerprint скопирован", Toast.LENGTH_SHORT).show();
        });
        box.addView(copy);
    }

    private void participant(JSONObject p, String name, boolean canAdd, boolean canRemove) {
        String holder = p.optString("holder", "");
        if (!holder.matches("[0-9a-f]{32}")) return;
        int rights = p.optInt("rights", 0) & ALL, eff = p.optInt("eff", rights) & ALL;
        StringBuilder s = new StringBuilder();
        s.append(name == null ? "Участник" : name).append("  ·  ").append(NodeAdminActivity.brief(holder));
        s.append("\nПрава: ").append(rightsText(rights));
        if (eff != rights) s.append("\nДействует (с учётом согласия участника): ").append(rightsText(eff));
        if (p.has("queued")) s.append("\nВ очереди: ").append(rightsText(p.optInt("queued", 0) & ALL));
        text("\n" + s, 14, false, 0);
        Button edit = new Button(this);
        edit.setText("Изменить права…");
        edit.setAllCaps(false);
        edit.setFilterTouchesWhenObscured(true);
        edit.setEnabled(!busy && (canAdd || canRemove));
        edit.setOnClickListener(v -> editDialog(holder, name, rights));
        box.addView(edit);
    }

    /** Чекбоксы USE..CONFIG; те, что у меня самого нет (grantable), недоступны. */
    private void editDialog(String holder, String name, int current) {
        int grantable = view == null ? 0 : view.optInt("grantable", 0) & ALL;
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(48, 16, 48, 0);
        CheckBox[] boxes = new CheckBox[BITS.length];
        for (int i = 0; i < BITS.length; i++) {
            CheckBox c = new CheckBox(this);
            c.setText(NAMES[i] + " — " + HINTS[i]);
            c.setChecked((current & BITS[i]) != 0);
            c.setEnabled((grantable & BITS[i]) != 0);
            boxes[i] = c;
            col.addView(c);
        }
        new AlertDialog.Builder(this).setTitle("Права: " + (name == null ? NodeAdminActivity.brief(holder) : name))
                .setView(col).setNegativeButton("Отмена", null)
                .setPositiveButton("Далее", (d, w) -> {
                    int next = 0;
                    for (int i = 0; i < BITS.length; i++) if (boxes[i].isChecked()) next |= BITS[i];
                    if (next == current) { Toast.makeText(this, "Права не изменились", Toast.LENGTH_SHORT).show(); return; }
                    confirm(holder, name, current, next);
                }).show();
    }

    private void confirm(String holder, String name, int current, int next) {
        int grantable = view == null ? 0 : view.optInt("grantable", 0) & ALL;
        boolean revokeAll = next == 0, widens = (next & ~current) != 0;
        // как в Trust::issue: пустые права (отзыв) требуют REMOVE, любые другие - ADD и подмножество своих прав
        if (revokeAll && !view.optBoolean("can_remove", false)) { notice("Нет права REMOVE: снять все права нельзя."); return; }
        if (!revokeAll && !view.optBoolean("can_add", false)) { notice("Нет права ADD: менять права нельзя."); return; }
        if ((next & ~grantable) != 0) { notice("Нельзя выдать права, которых нет у вас."); return; }
        StringBuilder m = new StringBuilder();
        m.append("Участник: ").append(name == null ? "" : name + " ").append(NodeAdminActivity.brief(holder));
        m.append("\nБыло: ").append(rightsText(current)).append("\nСтанет: ").append(revokeAll ? "ничего (все права снимаются)" : rightsText(next));
        if ((next & USE) == 0 && !revokeAll) m.append("\n\nБез USE участник пропадёт из сети.");
        if ((next & ~current & (ADD | REMOVE | CONFIG)) != 0) m.append("\n\nВы выдаёте административные права: участник сможет сам менять права других.");
        m.append("\n\nЗапись подписывается этим телефоном и уходит в очередь; применение на других нодах не подтверждается.");
        new AlertDialog.Builder(this).setTitle(revokeAll ? "Снять все права?" : "Изменить права?").setMessage(m.toString())
                .setNegativeButton("Назад", null)
                .setPositiveButton("Подтвердить", (d, w) -> submit(holder, next)).show();
    }

    private void submit(String holder, int rights) {
        if (busy || !holder.matches("[0-9a-f]{32}") || (rights & ~ALL) != 0) return;
        busy = true;
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
            runOnUiThread(() -> {
                busy = false;
                if (isFinishing() || isDestroyed()) return;
                notice(shown);
                lastKey = "";
                refresh();
            });
        }, "knothop-mynode-set").start();
    }

    private void notice(String s) { notice = s; lastKey = ""; render(); }

    /** Имена участников из таблицы выходов status.json (поле id - identity-хеш). Недоверенные подсказки, только для показа. */
    private Map<String, String> names() {
        Map<String, String> m = new HashMap<>();
        try {
            JSONArray ex = new JSONObject(Util.read(new File(state, "status.json"))).optJSONArray("exits");
            for (int i = 0; ex != null && i < ex.length(); i++) {
                JSONObject e = ex.optJSONObject(i);
                String id = e == null ? "" : e.optString("id", "").toLowerCase(Locale.ROOT);
                if (id.matches("[0-9a-f]{32}")) m.put(id, clip(TopologyView.shortName(e.optString("n", "?"))));
            }
        } catch (Throwable ignored) { }
        return m;
    }

    private static String rightsText(int mask) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < BITS.length; i++) if ((mask & BITS[i]) != 0) b.append(b.length() == 0 ? "" : ", ").append(NAMES[i]);
        return b.length() == 0 ? "нет" : b.toString();
    }

    private static String clip(String s) {
        String v = s == null ? "" : s.replaceAll("[\\p{Cntrl}]", " ");
        return v.length() > 120 ? v.substring(0, 120) + "…" : v;
    }

    private void text(String value, int size, boolean bold, int color) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(size);
        t.setPadding(0, 4, 0, 4);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        if (color != 0) t.setTextColor(Ui.ink(this, color));
        box.addView(t);
    }
}
