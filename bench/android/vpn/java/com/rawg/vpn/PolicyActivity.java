package com.rawg.vpn;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * «Мои права» (ADR 0015): по каждой сети, где админ что-то мне выдал, - выдано (потолок), на что я согласен и что действует сейчас.
 * Согласие - подписанная мной политика: она только сужает выданное. Управляет ею клиентский rawgd через state/policy-want.json
 * (корень -> биты), статус читает из state/status.json (поле policy). USE остаётся всегда, иначе нода пропадает из сети.
 */
public class PolicyActivity extends Activity {
    private static final int USE = 1, TRANSIT = 2, EXIT = 4, ADD = 8, REMOVE = 16, CONFIG = 32;
    private static final int GREY = 0xFF777777, GREEN = 0xFF2E9E4F;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private File state;
    private LinearLayout box;
    private String lastShown = "";
    private boolean binding;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        state = new File(getFilesDir(), "state");
        ScrollView sv = new ScrollView(this);
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(24, 48, 24, 48);
        sv.addView(box);
        setContentView(sv);
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(tick);
    }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            try { render(); } catch (Throwable ignored) { }
            ui.postDelayed(this, 2000);
        }
    };

    /** Выключатель доступен только там, где право работает на телефоне. EXIT: нет NAT и форвардинга без root (0015). TRANSIT: телефон не принимает соседние Link. */
    static boolean canToggle(int bit) {
        return false;
    }

    private static String why(int bit) {
        if (bit == EXIT) return "на телефоне выход невозможен (нет NAT без root)";
        if (bit == TRANSIT) return "телефон пока не принимает соседние Link";
        return "";
    }

    private void render() throws Exception {
        String js = Util.read(new File(state, "status.json"));
        if (js.isEmpty()) { show(null); return; }
        JSONArray pol = new JSONObject(js).optJSONArray("policy");
        String own = "";
        try { own = new JSONObject(Util.read(new File(state, "whoami.json"))).optString("hash", ""); } catch (Throwable ignored) { }
        String key = String.valueOf(pol) + own;
        if (key.equals(lastShown)) return;
        lastShown = key;
        show(pol);
    }

    private void show(JSONArray pol) throws Exception {
        box.removeAllViews();
        TextView title = new TextView(this);
        title.setText("Мои права");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        box.addView(title);
        TextView hint = new TextView(this);
        hint.setText("Права выдаёт администратор сети. Здесь видно, на что вы согласны: это только сужает выданное и расширить не может. Нода без действующих прав скрывается из списков.");
        hint.setTextSize(12);
        hint.setTextColor(GREY);
        box.addView(hint);
        String own = "";
        try { own = new JSONObject(Util.read(new File(state, "whoami.json"))).optString("hash", ""); } catch (Throwable ignored) { }
        int shown = 0;
        for (int i = 0; pol != null && i < pol.length(); i++) {
            JSONObject p = pol.getJSONObject(i);
            String root = p.optString("root", "");
            if (root.equals(own)) continue;   // собственная сеть: тут я админ, политика не нужна
            shown++;
            card(p, root);
        }
        if (shown == 0) {
            TextView none = new TextView(this);
            none.setText("\nВы пока не вступили ни в одну чужую сеть, либо приложение не запущено.");
            box.addView(none);
        }
    }

    private void card(JSONObject p, String root) {
        int grant = p.optInt("grant"), eff = p.optInt("eff");
        int offer = p.has("offer") && !p.isNull("offer") ? p.optInt("offer") : USE;   // без настройки клиент по умолчанию предлагает только USE
        TextView t = new TextView(this);
        t.setText("\nСеть " + p.optString("tag", root.substring(0, Math.min(8, root.length()))));
        t.setTypeface(Typeface.DEFAULT_BOLD);
        box.addView(t);
        TextView st = new TextView(this);
        st.setTextSize(12);
        st.setTextColor(eff == 0 ? 0xFFB33A3A : GREEN);
        st.setText(eff == 0 ? "Вы скрыты: действующих прав нет." : "Действует: " + names(eff));
        box.addView(st);
        addRow(root, "Использовать выходы сети", USE, grant, offer, true);
        addRow(root, "Быть транзитом для других", TRANSIT, grant, offer, false);
        addRow(root, "Быть выходом в интернет", EXIT, grant, offer, false);
        int admin = grant & (ADD | REMOVE | CONFIG);
        if (admin != 0) {
            TextView a = new TextView(this);
            a.setTextSize(12);
            a.setTextColor(GREY);
            a.setText("Административные права (выдано): " + names(admin));
            box.addView(a);
        }
    }

    private void addRow(String root, String label, int bit, int grant, int offer, boolean always) {
        Switch sw = new Switch(this);
        sw.setText(label);
        boolean granted = (grant & bit) != 0;
        binding = true;
        sw.setChecked(granted && (offer & bit) != 0);
        binding = false;
        sw.setEnabled(granted && !always && canToggle(bit));
        box.addView(sw);
        String note = !granted ? "не выдано администратором" : always ? "всегда включено" : canToggle(bit) ? "" : why(bit);
        if (!note.isEmpty()) {
            TextView n = new TextView(this);
            n.setTextSize(11);
            n.setTextColor(GREY);
            n.setPadding(96, 0, 0, 8);
            n.setText(note);
            box.addView(n);
        }
        sw.setOnCheckedChangeListener((CompoundButton v, boolean on) -> { if (!binding) set(root, bit, on, offer); });
    }

    private void set(String root, int bit, boolean on, int offer) {
        int next = on ? (offer | bit) : (offer & ~bit);
        try {
            JSONObject want;
            File f = new File(state, "policy-want.json");
            try { want = new JSONObject(Util.read(f)); } catch (Throwable t) { want = new JSONObject(); }
            want.put(root, next | USE);
            File tmp = new File(state, "policy-want.json.tmp");
            Files.write(tmp.toPath(), want.toString().getBytes(StandardCharsets.UTF_8));
            Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Throwable ignored) { }
    }

    static String names(int r) {
        StringBuilder s = new StringBuilder();
        String[] n = {"использовать", "транзит", "выход", "добавлять", "отзывать", "настраивать"};
        for (int i = 0; i < n.length; i++) if ((r & (1 << i)) != 0) { if (s.length() > 0) s.append(", "); s.append(n[i]); }
        return s.length() == 0 ? "ничего" : s.toString();
    }
}
