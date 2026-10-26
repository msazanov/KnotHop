package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;

/** Target-bound view over durable native admin state. No Android-owned command queue. */
public final class NodeAdminActivity extends Activity {
    static final String EXTRA_TARGET = "admin_target";
    static final String EXTRA_NAME = "admin_name";
    static final String EXTRA_FINGERPRINT = "admin_fingerprint";

    private static final int USE = 1, TRANSIT = 2, EXIT = 4, ADD = 8, REMOVE = 16, CONFIG = 32, HOST_ACCESS = 64;
    private static final int KNOWN = 127;
    private static final int[] RIGHT_BITS = {USE, TRANSIT, EXIT, ADD, REMOVE, CONFIG, HOST_ACCESS};
    private static final String[] RIGHT_NAMES = {"USE", "TRANSIT", "EXIT", "ADD", "REMOVE", "CONFIG", "HOST_ACCESS"};
    private final Handler ui = new Handler(Looper.getMainLooper());
    private File state;
    private LinearLayout box;
    private String target, targetName, openedFingerprint, selectedRoot = "";
    private JSONObject view;
    private boolean busy, resumed;
    private long lastManualRefresh;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        state = new File(getFilesDir(), "state");
        target = getIntent().getStringExtra(EXTRA_TARGET);
        targetName = safe(getIntent().getStringExtra(EXTRA_NAME), "Нода", 96);
        openedFingerprint = cleanHash(getIntent().getStringExtra(EXTRA_FINGERPRINT));
        if (!validDest(target)) { finish(); return; }
        ScrollView scroll = new ScrollView(this);
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(24, 36, 24, 32);
        scroll.addView(box);
        setContentView(scroll);
    }

    @Override protected void onResume() { super.onResume(); resumed = true; ui.post(tick); }
    @Override protected void onPause() { resumed = false; ui.removeCallbacks(tick); super.onPause(); }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            refreshLocal();
            if (resumed) ui.postDelayed(this, 1000);
        }
    };

    private void refreshLocal() {
        if (busy) return;
        busy = true;
        new Thread(() -> {
            JSONObject result = null;
            String error = "";
            try {
                String raw = Native.runCLI("admin-view --state " + state.getAbsolutePath() + " --target " + target, state.getAbsolutePath());
                if (raw == null || raw.length() > 65536) throw new Exception("Ответ backend пуст или превышает лимит");
                result = new JSONObject(raw);
                if (result.has("error")) { error = "Backend admin-view: " + AdminStatusText.reason(str(result, "error")); result = null; }
            } catch (Throwable e) { error = "Backend admin-view недоступен: " + e.getClass().getSimpleName(); }
            final JSONObject got = result;
            final String why = error;
            runOnUiThread(() -> {
                busy = false;
                if (isFinishing() || isDestroyed()) return;
                if (got != null) view = got;
                render(why);
            });
        }, "knothop-admin-view").start();
    }

    private void render(String backendError) {
        box.removeAllViews();
        String currentFingerprint = targetFingerprint();
        boolean targetMatches = !openedFingerprint.isEmpty() && openedFingerprint.equals(currentFingerprint);
        text("Управление нодой", 22, true);
        text(targetName + "  ·  fp " + brief(openedFingerprint) + "\nОтдельный выбранный VPN-выход не меняется этим экраном.", 15, true);
        if (!openedFingerprint.isEmpty() && !targetMatches) text("Отпечаток цели изменился или больше не подтверждается. Изменения заблокированы.", 14, false);
        if (backendError != null && !backendError.isEmpty()) text(backendError, 13, false);
        Button refresh = button("Обновить", v -> manualRefresh());
        refresh.setEnabled(false);
        box.addView(refresh);
        if (view == null) {
            text("Нет свежего локального снимка ноды.", 14, false);
            disabled("Удалённое управление недоступно: backend не сообщил capabilities и effective authority.");
            return;
        }
        JSONObject node = view.optJSONObject("node");
        if (node != null) {
            text("Состояние: " + AdminStatusText.nodeState(str(node, "status"), node.optBoolean("stale", false)), 14, false);
        } else text("Статус target-ноды не предоставлен backend.", 13, false);

        JSONObject caps = view.optJSONObject("capabilities");
        JSONObject authority = view.optJSONObject("effective_authority");
        if (authority == null) {
            text("Права для (этот актор, эта нода) не определены.", 14, false);
            disabled("Недоступно: backend не вернул effective authority.");
            return;
        }
        JSONArray authorities = authority.optJSONArray("authorities");
        text("Authority для этой пары", 16, true);
        text(AdminStatusText.reason(str(authority, "reason")), 13, false);
        if (authorities != null) {
            for (int i = 0; i < authorities.length(); i++) {
                JSONObject a = authorities.optJSONObject(i);
                if (a == null) continue;
                String root = cleanHash(str(a, "root"));
                text("Root " + brief(root) + " · " + (a.optBoolean("trusted") ? "anchor принят" : "anchor не подтверждён")
                        + " · scope " + safe(str(a, "scope"), "?", 24) + " · права: " + rightsNames(a.optInt("rights", 0))
                        + (a.has("reason") && !a.isNull("reason") ? "\n" + AdminStatusText.reason(str(a, "reason")) : ""), 12, false);
            }
        }
        chooseRoot(authorities);
        JSONObject selectedAuthority = selectedAuthority(authorities);
        boolean canStatus = caps != null && caps.optBoolean("status_get", false) && selectedAuthority != null
                && selectedAuthority.optBoolean("can_status", false);
        refresh.setEnabled(canStatus && targetMatches && !selectedRoot.isEmpty());
        if (!refresh.isEnabled()) disabled("Обновление с target-ноды недоступно: нет status.get capability/authority, выбранного root или актуального fingerprint.");

        JSONArray participants = view.optJSONArray("participants");
        if (caps == null || !caps.optBoolean("participants_export", false) || participants == null) {
            text("Список участников скрыт: экспорт не разрешён или не поддерживается target-нодой.", 13, false);
        } else {
            text("Участники и права", 17, true);
            for (int i = 0; i < participants.length(); i++) {
                JSONObject participant = participants.optJSONObject(i);
                if (participant != null) participant(participant, selectedAuthority, caps, targetMatches);
            }
        }
        text("Команды", 17, true);
        if (caps == null || !caps.optBoolean("admin_commands", false)) disabled("Backend не объявил поддержку адресных команд.");
        else if (!targetMatches) disabled("Цель не совпадает с отпечатком при открытии.");
        else if (selectedRoot.isEmpty() || selectedAuthority == null) disabled("Нужно выбрать конкретный root authority для этой операции.");
        else {
            addGrantControl(selectedAuthority, caps);
        }
        JSONArray pending = view.optJSONArray("commands");
        text("Состояние команд", 17, true);
        if (pending == null || pending.length() == 0) text("Нет сохранённых backend-команд.", 13, false);
        else for (int i = 0; i < pending.length(); i++) {
            JSONObject cmd = pending.optJSONObject(i);
            if (cmd != null) text(commandLine(cmd), 13, false);
        }
    }

    /** Почему HOST_ACCESS недоступен: причина выбранного root, иначе общая причина capabilities. */
    private String hostAccessWhy(JSONObject authority, JSONObject caps) {
        String why = authority == null ? "" : str(authority, "reason");
        if (why.isEmpty() && caps != null) why = str(caps, "reason");
        return why;
    }

    private void participant(JSONObject p, JSONObject authority, JSONObject caps, boolean targetMatches) {
        String holder = cleanHash(str(p, "holder"));
        int rights = p.optInt("rights", 0);
        boolean hostAccess = p.optBoolean("host_access", false);
        text("Участник · fp " + brief(holder) + "\nПрава: " + rightsNames(rights)
                + "\nHOST_ACCESS: " + (hostAccess ? "действует (решение ноды)" : "нет"), 14, false);
        if (authority == null || !caps.optBoolean("admin_commands", false) || !targetMatches || selectedRoot.isEmpty() || !validHolder(holder)) {
            disabled("Изменение недоступно: нет capability, authority или совпадения target.");
            return;
        }
        boolean hostOk = caps.optBoolean("host_access", false);
        boolean canGrant = hostOk && authority.optBoolean("can_grant", false) && caps.optBoolean("rights_grant", false)
                && (authority.optInt("grantable_rights", 0) & HOST_ACCESS) != 0 && (rights & ~KNOWN) == 0;
        boolean canRevoke = hostOk && authority.optBoolean("can_revoke", false) && caps.optBoolean("rights_revoke", false)
                && (authority.optInt("revocable_rights", 0) & HOST_ACCESS) != 0;
        if (!hostOk) { disabled(AdminStatusText.reason(hostAccessWhy(authority, caps).isEmpty() ? "target_host_access_unavailable" : hostAccessWhy(authority, caps))); return; }
        if (hostAccess ? !canRevoke : !canGrant) { disabled("Нет права " + (hostAccess ? "отзыва" : "выдачи") + " HOST_ACCESS у участника на этой ноде."); return; }
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        if (hostAccess) row.addView(button("Отозвать HOST_ACCESS…", v -> editRights(holder, brief(holder), true)));
        else row.addView(button("Выдать HOST_ACCESS…", v -> editRights(holder, brief(holder), false)));
        box.addView(row);
    }

    private void addGrantControl(JSONObject authority, JSONObject caps) {
        boolean canGrant = authority.optBoolean("can_grant", false) && (authority.optInt("grantable_rights", 0) & HOST_ACCESS) != 0;
        if (!caps.optBoolean("host_access", false)) {
            String why = hostAccessWhy(authority, caps);
            disabled("HOST_ACCESS (64) недоступен: " + AdminStatusText.reason(why.isEmpty() ? "target_host_access_unavailable" : why) + ".");
            return;
        }
        boolean canRevoke = authority.optBoolean("can_revoke", false) && (authority.optInt("revocable_rights", 0) & HOST_ACCESS) != 0;
        if (canGrant && caps.optBoolean("rights_grant", false)) box.addView(button("Выдать HOST_ACCESS по fingerprint…", v -> askHolder(false)));
        else disabled("Выдача запрещена: у выбранного root нет права ADD/выдачи HOST_ACCESS на этой ноде.");
        // Отзыв по fingerprint не зависит от списка участников (он скрыт, пока у ноды больше одного сетевого корня).
        if (canRevoke && caps.optBoolean("rights_revoke", false)) box.addView(button("Отозвать HOST_ACCESS по fingerprint…", v -> askHolder(true)));
        else disabled("Отзыв запрещён: у выбранного root нет права REMOVE/отзыва HOST_ACCESS на этой ноде.");
        text("HOST_ACCESS (64): выдаётся и отзывается только в области этой ноды (scope NODE), не на весь корень.", 13, false);
    }

    private void askHolder(boolean revoke) {
        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setHint("fingerprint holder (32 hex)");
        new AlertDialog.Builder(this).setTitle("Целевой holder")
                .setMessage("Введите fingerprint identity. Проверьте его перед " + (revoke ? "отзывом" : "выдачей") + " прав.")
                .setView(input).setNegativeButton("Отмена", null)
                .setPositiveButton("Далее", (d, w) -> {
                    String holder = cleanHash(input.getText().toString().trim());
                    if (!validHolder(holder)) { render("Holder должен быть fingerprint identity из 32 hex-символов."); return; }
                    editRights(holder, brief(holder), revoke);
                }).show();
    }

    /**
     * Выдача и отзыв: ровно HOST_ACCESS. Обычные права не затрагиваются, экспорт участников не нужен.
     * Область всегда NODE, root — выбранный; backend проверяет известность держателя и полномочия.
     */
    private void editRights(String holder, String holderName, boolean revoke) {
        if (!validHolder(holder) || !targetUnchanged()) { render("Цель или holder не подтверждены; действие отменено."); return; }
        JSONObject auth = selectedAuthority(view == null ? null : authoritiesOf(view));
        if (auth == null || selectedRoot.isEmpty()) { render("Нужно выбрать конкретный root authority."); return; }
        JSONObject caps = view.optJSONObject("capabilities");
        int allowed = revoke ? auth.optInt("revocable_rights", 0) : auth.optInt("grantable_rights", 0);
        if (caps == null || !caps.optBoolean("host_access", false) || (allowed & HOST_ACCESS) == 0) {
            render("Backend не разрешил " + (revoke ? "отзыв" : "выдачу") + " HOST_ACCESS для выбранной authority.");
            return;
        }
        confirmAction(revoke, holder, holderName, HOST_ACCESS);
    }

    private void confirmAction(boolean revoke, String holder, String holderName, int rights) {
        if (!targetUnchanged()) { render("Отпечаток цели изменился; команда заблокирована."); return; }
        String action = revoke ? "Отозвать HOST_ACCESS у " + holderName + " (" + brief(holder) + ")"
                : "Выдать HOST_ACCESS для " + holderName + " (" + brief(holder) + "); остальные права держателя не меняются";
        new AlertDialog.Builder(this).setTitle("Подтверждение target-команды")
                .setMessage(action + "\nНа ноде " + targetName + " (fp " + brief(openedFingerprint) + "), scope: только эта нода, root " + brief(selectedRoot) + "."
                        + "\nДоставка или локальное принятие не означают применение; о выдаче или отзыве скажет только действующее решение ноды.")
                .setNegativeButton("Назад", null)
                .setPositiveButton("Отправить запрос", (d, w) -> submit(revoke ? AdminStatusText.OP_REVOKE : AdminStatusText.OP_GRANT, holder, rights, holderName))
                .show();
    }

    private void submit(String op, String holder, int rights, String holderName) {
        if (busy || !validHolder(holder) || !targetUnchanged()) { render("Действие остановлено: цель или данные изменились."); return; }
        JSONObject auth = selectedAuthority(view == null ? null : authoritiesOf(view));
        if (auth == null || selectedRoot.isEmpty()) { render("Нет подтверждённой authority для выбранного корня."); return; }
        if ((rights & HOST_ACCESS) == 0 || (rights & ~KNOWN) != 0 || (op.equals(AdminStatusText.OP_REVOKE) && rights != HOST_ACCESS)) {
            render("Некорректная маска прав; запрос не создан."); return;
        }
        String id = UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        String command = "admin-submit --state " + state.getAbsolutePath() + " --target " + target + " --root " + selectedRoot
                + " --op " + op + " --holder " + holder + " --rights " + rights + " --scope NODE --request-id " + id;
        busy = true;
        new Thread(() -> {
            String result = "";
            try {
                String raw = Native.runCLI(command, state.getAbsolutePath());
                if (raw == null || raw.length() > 8192) throw new Exception("invalid backend response");
                result = AdminStatusText.submit(new JSONObject(raw), op);
            } catch (Throwable e) { result = "Backend не подтвердил запрос (" + e.getClass().getSimpleName() + "). Не считайте его отправленным."; }
            final String msg = result;
            runOnUiThread(() -> {
                busy = false;
                if (isFinishing() || isDestroyed()) return;
                new AlertDialog.Builder(this).setTitle("Команда для " + holderName)
                        .setMessage(targetName + " · fp " + brief(openedFingerprint) + "\n" + msg)
                        .setPositiveButton("Готово", (d, w) -> refreshLocal()).show();
            });
        }, "knothop-admin-submit").start();
    }

    private void manualRefresh() {
        JSONObject caps = view == null ? null : view.optJSONObject("capabilities");
        JSONObject selected = selectedAuthority(view == null ? null : authoritiesOf(view));
        if (caps == null || !caps.optBoolean("status_get", false) || selected == null || selectedRoot.isEmpty()
                || !selected.optBoolean("can_status", false)) {
            render("Обновление target-статуса недоступно: backend не подтвердил capability и authority.");
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastManualRefresh < 10000) { text("Обновлять можно не чаще раза в 10 секунд.", 12, false); return; }
        lastManualRefresh = now;
        if (!targetUnchanged()) { render("Отпечаток цели изменился; команды заблокированы."); return; }
        String actor = ownHolder();
        if (!validHolder(actor)) { render("Локальная identity не готова; status.get не отправлен."); return; }
        String command = "admin-submit --state " + state.getAbsolutePath() + " --target " + target + " --root " + selectedRoot
                + " --op " + AdminStatusText.OP_STATUS + " --holder " + actor + " --rights 0 --scope NODE --request-id " + UUID.randomUUID().toString().replace("-", "");
        busy = true;
        new Thread(() -> {
            String problem = "";
            try {
                String raw = Native.runCLI(command, state.getAbsolutePath());
                if (raw == null || raw.isEmpty() || raw.length() > 8192) problem = "Backend не принял запрос обновления.";
                else {
                    JSONObject r = new JSONObject(raw);
                    if (!r.optBoolean("accepted", false)) problem = AdminStatusText.submit(r, AdminStatusText.OP_STATUS);
                }
            } catch (Throwable e) { problem = "Backend не принял запрос обновления (" + e.getClass().getSimpleName() + ")."; }
            final String why = problem;
            runOnUiThread(() -> { busy = false; if (isFinishing() || isDestroyed()) return; if (!why.isEmpty()) render(why); else refreshLocal(); });
        }, "knothop-admin-refresh").start();
    }

    private boolean targetUnchanged() { return !openedFingerprint.isEmpty() && openedFingerprint.equals(targetFingerprint()); }

    private String targetFingerprint() {
        try {
            JSONArray exits = new JSONObject(Util.read(new File(state, "status.json"))).optJSONArray("exits");
            for (int i = 0; exits != null && i < exits.length(); i++) {
                JSONObject e = exits.optJSONObject(i);
                if (e != null && target.equals(e.optString("d"))) {
                    String fp = cleanHash(e.optString("id", ""));
                    return fp.isEmpty() ? cleanHash(e.optString("d", "")) : fp;
                }
            }
        } catch (Throwable ignored) { }
        return "";
    }

    private String ownHolder() {
        try { return cleanHash(new JSONObject(Util.read(new File(state, "whoami.json"))).optString("hash", "")); }
        catch (Throwable ignored) { return ""; }
    }

    private void chooseRoot(JSONArray authorities) {
        if (authorities == null || authorities.length() == 0) { selectedRoot = ""; return; }
        if (authorities.length() == 1) { selectedRoot = cleanHash(str(authorities.optJSONObject(0), "root")); return; }
        String[] labels = new String[authorities.length()];
        boolean stillPresent = false;
        for (int i = 0; i < labels.length; i++) {
            String root = cleanHash(str(authorities.optJSONObject(i), "root"));
            labels[i] = "root " + brief(root);
            stillPresent |= root.equals(selectedRoot);
        }
        if (!stillPresent) selectedRoot = "";
        String label = selectedRoot.isEmpty() ? "Выбрать root authority…" : "Root authority: " + brief(selectedRoot);
        box.addView(button(label, v -> new AlertDialog.Builder(this).setTitle("Authority для команды")
                .setItems(labels, (d, which) -> { selectedRoot = cleanHash(str(authorities.optJSONObject(which), "root")); render(""); })
                .setNegativeButton("Отмена", null).show()));
    }

    private static JSONArray authoritiesOf(JSONObject v) {
        JSONObject authority = v.optJSONObject("effective_authority");
        return authority == null ? null : authority.optJSONArray("authorities");
    }

    /** Authority выбранного root; без выбранного root или без совпадения — null (объединение по корням не строится). */
    private JSONObject selectedAuthority(JSONArray authorities) {
        if (authorities == null || selectedRoot.isEmpty()) return null;
        for (int i = 0; i < authorities.length(); i++) {
            JSONObject a = authorities.optJSONObject(i);
            if (a != null && selectedRoot.equals(cleanHash(str(a, "root")))) return a;
        }
        return null;
    }

    private String commandLine(JSONObject c) {
        String op = str(c, "op");
        String id = safe(str(c, "requestid"), "", 64);
        long updated = c.optLong("updated", 0);
        long age = updated > 0 ? Math.max(0, System.currentTimeMillis() / 1000 - updated) : 0;
        String verdict = AdminStatusText.describe(op, str(c, "state"), c.optBoolean("durable_ack", false), c.optJSONObject("result"), age);
        return brief(openedFingerprint) + " · " + opTitle(op) + (id.isEmpty() ? "" : " · " + id.substring(0, Math.min(8, id.length())))
                + (updated > 0 ? " · " + expiry(updated) : "") + "\n" + verdict;
    }

    private static String opTitle(String op) {
        switch (op) {
            case AdminStatusText.OP_STATUS: return "запрос статуса";
            case AdminStatusText.OP_GRANT: return "выдача HOST_ACCESS";
            case AdminStatusText.OP_REVOKE: return "отзыв HOST_ACCESS";
            default: return safe(op, "команда", 40);
        }
    }

    private static String str(JSONObject o, String key) { return o == null || !o.has(key) || o.isNull(key) ? "" : o.optString(key, ""); }

    private void text(String value, int size, boolean bold) {
        TextView t = new TextView(this); t.setText(safe(value, "", 500)); t.setTextSize(size); t.setPadding(0, 8, 0, 8);
        if (bold) t.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        box.addView(t);
    }
    private void disabled(String reason) { TextView t = new TextView(this); t.setText("Недоступно: " + safe(reason, "нет authority", 200)); t.setTextSize(12); t.setTextColor(0xFF777777); t.setPadding(0, 2, 0, 8); box.addView(t); }
    private Button button(String label, View.OnClickListener listener) { Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setOnClickListener(listener); b.setFilterTouchesWhenObscured(true); return b; }

    static String brief(String hash) { return hash == null || hash.isEmpty() ? "неизвестен" : hash.length() <= 12 ? hash : hash.substring(0, 8) + "…" + hash.substring(hash.length() - 4); }
    private static boolean validDest(String s) { return s != null && s.matches("[0-9a-fA-F]{32}"); }
    private static boolean validHolder(String s) { return s != null && s.matches("[0-9a-f]{32}"); }
    private static String cleanHash(String s) { return s != null && s.matches("[0-9a-fA-F]{32,128}") ? s.toLowerCase(Locale.ROOT) : ""; }
    private static String safe(String s, String fallback, int max) { if (s == null || s.isEmpty()) return fallback; String v = s.replaceAll("[\\p{Cntrl}]", " "); return v.length() > max ? v.substring(0, max) + "…" : v; }
    private static String rightsNames(int mask) { StringBuilder b = new StringBuilder(); for (int i = 0; i < RIGHT_BITS.length; i++) if ((mask & RIGHT_BITS[i]) != 0) b.append(b.length() == 0 ? "" : ", ").append(RIGHT_NAMES[i]); return b.length() == 0 ? "нет" : b.toString(); }
    private static String expiry(long value) { if (value <= 0) return "неизвестно"; long ms = value < 100000000000L ? value * 1000 : value; return new SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(new Date(ms)); }
}
