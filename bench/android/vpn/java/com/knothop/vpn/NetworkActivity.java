package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Сеть с точки зрения этого телефона (ADR 0028 §2.7-2.8): ноды (контакты и управляемые), открытые и выданные приглашения, админы,
 * знакомство выбранных нод одной кнопкой и правка прав. Данные - из таблицы ноды и последних статусов управляемых нод
 * ({@code status.get/push}): полнота настолько, насколько ноды ответили. Все изменения - команды {@code node.cmd/1} с повтором до подтверждения.
 */
public final class NetworkActivity extends Activity {
    private LinearLayout box;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Map<String, CheckBox> picked = new HashMap<>();
    private JSONObject view = new JSONObject();
    private final Runnable tick = new Runnable() {
        @Override public void run() { reload(); ui.postDelayed(this, 5000); }
    };

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Ui.BG);
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(Ui.dp(this, 16), Ui.dp(this, 20), Ui.dp(this, 16), Ui.dp(this, 24));
        scroll.addView(box);
        setContentView(scroll);
        setTitle("Сеть");
    }

    @Override protected void onResume() { super.onResume(); ui.post(tick); }
    @Override protected void onPause() { super.onPause(); ui.removeCallbacks(tick); }

    private void reload() {
        new Thread(() -> {
            JSONObject v = Ctl.call(this, Ctl.req("view"));
            ui.post(() -> { view = v; render(); });
        }, "knothop-net-view").start();
    }

    private void cmd(JSONObject req, String done) {
        new Thread(() -> {
            JSONObject r = Ctl.call(this, req);
            ui.post(() -> {
                Toast.makeText(this, r.optBoolean("ok") ? done : "Не удалось: " + r.optString("error", "?"), Toast.LENGTH_LONG).show();
                reload();
            });
        }, "knothop-net-cmd").start();
    }

    private JSONObject managed() {
        JSONObject n = view.optJSONObject("nodes");
        return n == null ? new JSONObject() : n;
    }

    private void render() {
        // выбор галочек переживает перерисовку
        Map<String, Boolean> keep = new HashMap<>();
        for (Map.Entry<String, CheckBox> e : picked.entrySet()) keep.put(e.getKey(), e.getValue().isChecked());
        picked.clear();
        box.removeAllViews();
        box.addView(Ui.titleWithHelp(this, "Сеть",
                "Сеть — не отдельный объект: это ноды, которые вы знаете, и права, которые каждая нода выдала соседям. Корня и общего ключа нет. "
                + "Здесь видны только ноды, которыми вы управляете (они присылают статус), и их соседи; офлайн-нода показывается по последнему статусу."));
        if (!view.optBoolean("ok", true) && view.has("error")) {
            box.addView(Ui.text(this, view.optString("error"), 13, Ui.ORANGE, false));
            return;
        }
        if (view.optBoolean("offline")) box.addView(Ui.text(this, "Нода не запущена: показана таблица с диска. Включите «Сеть» на главном экране.", 12, Ui.ORANGE, false));
        renderNodes(keep);
        renderP2p();
        renderInvites();
        renderAdmins();
    }

    private String nameOf(String hash, JSONArray contacts) {
        for (int i = 0; contacts != null && i < contacts.length(); i++) {
            JSONObject c = contacts.optJSONObject(i);
            if (hash.equals(c.optString("hash")) && !c.optString("name").isEmpty()) return Rights.clip(c.optString("name"));
        }
        return hash.substring(0, 8);
    }

    /** Имя контакта, если оно есть, и короткий хеш («pixel  aabbccdd»); без имени - один хеш, без дубля. */
    private String label(String hash, JSONArray contacts) {
        String n = nameOf(hash, contacts), h = hash.substring(0, 8);
        return n.equals(h) ? h : n + "  " + h;
    }

    private void renderNodes(Map<String, Boolean> keep) {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.titleWithHelp(this, "Ноды",
                "Отметьте две и больше нод и нажмите «Познакомить»: для каждой пары создаются приглашения, ноды гасят их сами и становятся соседями "
                + "(взаимные права USE, дальше Link/QUIC по подсказкам адресов). Телефон можно выключить после постановки команд: они доставляются прямо или через PN. "
                + "Нода-транзит пересылает пакеты, быть PN и relay; нода-выход даёт выход в интернет; это свойства самой ноды."));
        JSONArray contacts = view.optJSONArray("contacts");
        JSONObject nodes = managed();
        List<String> shown = new ArrayList<>();
        for (int i = 0; contacts != null && i < contacts.length(); i++) {
            JSONObject c = contacts.optJSONObject(i);
            if (c != null && (c.optInt("roles") != 0 || nodes.has(c.optString("hash")))) shown.add(c.optString("hash"));
        }
        for (java.util.Iterator<String> it = nodes.keys(); it.hasNext(); ) { String h = it.next(); if (!shown.contains(h)) shown.add(h); }
        if (shown.isEmpty()) card.addView(Ui.muted(this, "Нод пока нет. Вступите по приглашению или выпустите приглашение для сервера."));
        for (String h : shown) {
            JSONObject entry = nodes.optJSONObject(h);
            JSONObject st = entry == null ? null : entry.optJSONObject("status");
            int roles = 0;
            for (int i = 0; contacts != null && i < contacts.length(); i++) if (h.equals(contacts.optJSONObject(i).optString("hash"))) roles = contacts.optJSONObject(i).optInt("roles");
            CheckBox cb = new CheckBox(this);
            cb.setTextColor(Ui.TEXT);
            long ageS = entry == null ? -1 : Math.max(0, System.currentTimeMillis() / 1000 - entry.optLong("at"));
            cb.setText(label(h, contacts) + "\n" + Rights.roles(roles) + (st == null ? "  ·  статуса нет" : "  ·  статус " + age(ageS) + " назад"));
            cb.setChecked(Boolean.TRUE.equals(keep.get(h)));
            picked.put(h, cb);
            card.addView(cb);
            if (st != null) {
                LinearLayout row = new LinearLayout(this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.addView(Ui.secondary(this, "Роли", v -> rolesDialog(h, st)), new LinearLayout.LayoutParams(0, -2, 1f));
                row.addView(Ui.secondary(this, "Права", v -> peersDialog(h, st)), new LinearLayout.LayoutParams(0, -2, 1f));
                card.addView(row);
            }
        }
        if (shown.size() >= 2) {
            card.addView(Ui.primary(this, "Познакомить выбранные", v -> introduce()), Ui.cardParams(this));
        }
        box.addView(card, Ui.cardParams(this));
    }

    /**
     * Устройства без серверов (P2P): прямое соединение QUIC с теми, с кем вы обменялись приглашениями. Честный статус вместо вечного «подключаюсь…».
     * Если у них нет EXIT, через них доступна только связь между устройствами, не выход в интернет.
     */
    private void renderP2p() {
        JSONArray p2p = null;
        try {
            String js = Util.read(new java.io.File(Ctl.state(this), "status.json"));
            if (!js.isEmpty()) p2p = new JSONObject(js).optJSONArray("p2p");
        } catch (Exception ignored) { }
        if (p2p == null || p2p.length() == 0) return;
        LinearLayout card = Ui.card(this);
        card.addView(Ui.titleWithHelp(this, "Устройства (P2P)",
                "Прямое соединение QUIC между устройствами без серверов: оно устанавливается по адресам, которые устройства прислали друг другу в приглашении (обычно это глобальный IPv6 "
                + "или IPv4 с проброшенным портом). Через публичный посредник соединение не строится: если оба устройства за NAT и IPv6 нет, прямая связь не получится. "
                + "Выход в интернет через такое устройство возможен, только если на нём включён EXIT; после QUIC действуют обычные права из таблицы."));
        for (int i = 0; i < p2p.length(); i++) {
            JSONObject e = p2p.optJSONObject(i);
            if (e == null) continue;
            String id = e.optString("id", "");
            card.addView(Ui.text(this, P2p.label(e), 14, Ui.TEXT, true));
            card.addView(Ui.text(this, P2p.text(e), 12, "direct".equals(e.optString("state")) ? Ui.GREEN : P2p.failed(e) ? Ui.ORANGE : Ui.MUTED, false));
            String cap = P2p.capability(e);
            if (!cap.isEmpty()) card.addView(Ui.muted(this, cap));
        }
        box.addView(card, Ui.cardParams(this));
    }

    private static String age(long s) {
        if (s < 90) return s + " с";
        if (s < 5400) return (s / 60) + " мин";
        return (s / 3600) + " ч";
    }

    private void introduce() {
        JSONArray ids = new JSONArray();
        for (Map.Entry<String, CheckBox> e : picked.entrySet()) if (e.getValue().isChecked()) ids.put(e.getKey());
        if (ids.length() < 2) { Toast.makeText(this, "Отметьте две ноды или больше", Toast.LENGTH_SHORT).show(); return; }
        new AlertDialog.Builder(this).setTitle("Познакомить " + ids.length() + " нод?")
                .setMessage("Каждая пара получит взаимные приглашения с правом USE. Команды доставляются нодам напрямую или через PN и повторяются до подтверждения.")
                .setPositiveButton("Познакомить", (d, w) -> {
                    try { cmd(Ctl.req("introduce").put("nodes", ids).put("rights", Rights.SERVER), "Команды знакомства поставлены в очередь"); } catch (Exception e) { /* не бывает */ }
                }).setNegativeButton("Отмена", null).show();
    }

    private void rolesDialog(String hash, JSONObject st) {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(48, 16, 48, 0);
        CheckBox tr = new CheckBox(this); tr.setText("Транзит: пересылать пакеты, быть PN и relay"); tr.setChecked(st.optBoolean("transit_enabled"));
        CheckBox ex = new CheckBox(this); ex.setText("Выход в интернет"); ex.setChecked(st.optBoolean("exit_enabled"));
        col.addView(tr); col.addView(ex);
        new AlertDialog.Builder(this).setTitle("Роли ноды").setView(col)
                .setPositiveButton("Применить", (d, w) -> {
                    try {
                        JSONArray ops = new JSONArray().put(new JSONObject().put("op", "config.set").put("transit_enabled", tr.isChecked()).put("exit_enabled", ex.isChecked()));
                        cmd(Ctl.req("ops").put("target", hash).put("ops", ops), "Команда поставлена в очередь");
                    } catch (Exception e) { /* не бывает */ }
                }).setNegativeButton("Отмена", null).show();
    }

    private void peersDialog(String hash, JSONObject st) {
        JSONArray peers = st.optJSONArray("peers");
        List<JSONObject> list = new ArrayList<>();
        for (int i = 0; peers != null && i < peers.length(); i++) if (peers.optJSONObject(i).optInt("rights") != 0) list.add(peers.optJSONObject(i));
        String[] labels = new String[list.size()];
        for (int i = 0; i < labels.length; i++) labels[i] = list.get(i).optString("hash").substring(0, 8) + "  " + Rights.clip(list.get(i).optString("name")) + "\n" + Rights.text(list.get(i).optInt("rights"));
        new AlertDialog.Builder(this).setTitle("Кому что разрешено на ноде").setItems(labels, (d, which) -> editRights(hash, list.get(which), st)).setNegativeButton("Закрыть", null).show();
    }

    private void editRights(String node, JSONObject peer, JSONObject st) {
        int cur = peer.optInt("rights");
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(48, 16, 48, 0);
        CheckBox[] cbs = new CheckBox[Rights.BITS.length];
        for (int i = 0; i < cbs.length; i++) {
            cbs[i] = new CheckBox(this);
            cbs[i].setText(Rights.NAMES[i] + " - " + Rights.HINTS[i]);
            cbs[i].setChecked((cur & Rights.BITS[i]) != 0);
            col.addView(cbs[i]);
        }
        boolean lastAdmin = (cur & Rights.CONFIG) != 0 && st.optJSONArray("controllers") != null && st.optJSONArray("controllers").length() <= 1;
        if (lastAdmin) col.addView(Ui.text(this, "Это последний админ ноды: после снятия CONFIG править сеть можно будет только с сервера.", 12, Ui.ORANGE, false));
        new AlertDialog.Builder(this).setTitle(peer.optString("hash").substring(0, 8)).setView(col)
                .setPositiveButton("Применить", (d, w) -> {
                    int r = 0;
                    for (int i = 0; i < cbs.length; i++) if (cbs[i].isChecked()) r |= Rights.BITS[i];
                    try {
                        JSONObject op = r == 0 ? new JSONObject().put("op", "peer.remove").put("hash", peer.optString("hash"))
                                : new JSONObject().put("op", "peer.set").put("pk", peer.optString("pk")).put("rights", r).put("name", peer.optString("name"));
                        cmd(Ctl.req("ops").put("target", node).put("ops", new JSONArray().put(op)), "Команда поставлена в очередь");
                    } catch (Exception e) { /* не бывает */ }
                })
                .setNeutralButton("Отозвать всё", (d, w) -> {
                    try {
                        JSONObject op = new JSONObject().put("op", "peer.remove").put("hash", peer.optString("hash"));
                        cmd(Ctl.req("ops").put("target", node).put("ops", new JSONArray().put(op)), "Отзыв поставлен в очередь");
                    } catch (Exception e) { /* не бывает */ }
                }).setNegativeButton("Отмена", null).show();
    }

    private void renderInvites() {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.titleWithHelp(this, "Приглашения",
                "Открытые - ещё не погашены: любой, у кого есть строка, может её использовать. Выданные - кто-то уже погасил: проверьте его хеш и при необходимости "
                + "отзовите права. Команды выпуска ждут в очереди, пока нода не подтвердит."));
        JSONArray contacts = view.optJSONArray("contacts");
        List<String> open = new ArrayList<>(), issued = new ArrayList<>();
        collectInvites(open, issued, "этот телефон", view.optJSONArray("invites"), contacts);
        JSONObject nodes = managed();
        for (java.util.Iterator<String> it = nodes.keys(); it.hasNext(); ) {
            String h = it.next();
            JSONObject st = nodes.optJSONObject(h).optJSONObject("status");
            if (st != null) collectInvites(open, issued, label(h, contacts), st.optJSONArray("invites"), contacts);
        }
        if (!open.isEmpty()) {
            card.addView(Ui.text(this, "Открытые: " + open.size(), 13, Ui.TEXT, true));
            for (String l : open) card.addView(Ui.text(this, "• " + l, 12, Ui.TEXT, false));
        }
        if (!issued.isEmpty()) {
            LinearLayout.LayoutParams gp = Ui.cardParams(this);
            card.addView(Ui.text(this, "Выданные (погашены): " + issued.size(), 13, Ui.TEXT, true), open.isEmpty() ? new LinearLayout.LayoutParams(-1, -2) : gp);
            for (String l : issued) card.addView(Ui.text(this, "• " + l, 12, Ui.MUTED, false));
        }
        JSONArray ob = view.optJSONArray("outbox");
        int pending = 0;
        for (int i = 0; ob != null && i < ob.length(); i++) if ("pending".equals(ob.optJSONObject(i).optString("state"))) pending++;
        if (pending > 0) card.addView(Ui.text(this, "Команд ждёт подтверждения нод: " + pending, 12, Ui.ORANGE, false));
        JSONObject pend = view.optJSONObject("pending");
        JSONArray pairs = pend == null ? null : pend.optJSONArray("pairs");
        if (pairs != null && pairs.length() > 0) {
            StringBuilder who = new StringBuilder();
            for (int i = 0; i < pairs.length(); i++) who.append(i == 0 ? "" : ", ").append(label(pairs.optJSONObject(i).optString("h", "00000000"), contacts));
            card.addView(Ui.text(this, "Моё вступление: пар погашено " + done(pairs) + " из " + pairs.length() + " (ждёт анонсов нод): " + who, 12, Ui.ORANGE, false));
        }
        if (open.isEmpty() && issued.isEmpty() && pending == 0 && (pairs == null || pairs.length() == 0)) card.addView(Ui.muted(this, "Приглашений нет."));
        box.addView(card, Ui.cardParams(this));
    }

    private static int done(JSONArray pairs) {
        int d = 0;
        for (int i = 0; i < pairs.length(); i++) if ("done".equals(pairs.optJSONObject(i).optString("state"))) d++;
        return d;
    }

    /** Приглашения одной ноды: открытые («где: осталось, права») и выданные («где: кому - имя и хеш, права»). */
    private void collectInvites(List<String> open, List<String> issued, String where, JSONArray inv, JSONArray contacts) {
        for (int i = 0; inv != null && i < inv.length(); i++) {
            JSONObject x = inv.optJSONObject(i);
            if (x == null) continue;
            String st = x.optString("state");
            if (!"open".equals(st) && !"redeemed".equals(st) && !"settled".equals(st)) continue;
            String rights = "  ·  права принявшего: " + Rights.text(x.optInt("rights"));
            if ("open".equals(st)) {
                open.add(where + ": осталось " + age(x.optLong("left_s")) + rights);
            } else {
                String by = x.optString("by", "null");
                issued.add(where + ": " + (by.length() >= 8 && !"null".equals(by) ? "принял " + label(by, contacts) : "принято") + rights);
            }
        }
    }

    private void renderAdmins() {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.titleWithHelp(this, "Админы",
                "Админ — держатель CONFIG на ноде. Админы равны и могут снимать друг друга; если админов не осталось, нода работает дальше, но править сеть можно только "
                + "локально на сервере (knothopd peers --offline) или новым приглашением."));
        JSONObject nodes = managed();
        JSONArray contacts = view.optJSONArray("contacts");
        String me = view.optString("me", "");
        int n = 0;
        for (java.util.Iterator<String> it = nodes.keys(); it.hasNext(); ) {
            String h = it.next();
            JSONObject st = nodes.optJSONObject(h).optJSONObject("status");
            JSONArray ctl = st == null ? null : st.optJSONArray("controllers");
            for (int i = 0; ctl != null && i < ctl.length(); i++) {
                String a = ctl.optString(i);
                n++;
                String line = nameOf(h, contacts) + ": " + (a.equals(me) ? "я" : a.substring(0, 8));
                card.addView(Ui.text(this, line, 12, Ui.TEXT, false));
                if (!a.equals(me)) {
                    final String admin = a, node = h;
                    card.addView(Ui.secondary(this, "Снять админа на " + nameOf(h, contacts), v -> new AlertDialog.Builder(this).setTitle("Снять админа?")
                            .setMessage("Админ " + admin.substring(0, 8) + " потеряет права управления нодой " + nameOf(node, contacts) + ". Админы равны: это можно сделать любому.")
                            .setPositiveButton("Снять", (d, w) -> {
                                try { cmd(Ctl.req("ops").put("target", node).put("ops", new JSONArray().put(new JSONObject().put("op", "peer.remove").put("hash", admin))), "Команда поставлена в очередь"); } catch (Exception e) { /* не бывает */ }
                            }).setNegativeButton("Отмена", null).show()));
                }
            }
        }
        if (n == 0) card.addView(Ui.muted(this, "Нет данных (нужен статус управляемых нод)."));
        box.addView(card, Ui.cardParams(this));
    }
}
