package com.rawg.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Вкладка «Маршрутизация». Три режима: авто, приоритеты выходов, правила по спискам (geoip/geosite проекта runetfreedom) с ручными
 * записями. Изменения сохраняются сразу в state/routing.json; запущенный клиент подхватывает их за секунду. Исключение - правила
 * «мимо VPN»: они задают исключённые маршруты туннеля и применяются при следующем подключении.
 */
public class RoutingActivity extends Activity {
    private static final int GREEN = 0xFF2E9E4F, GREY = 0xFF777777;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private File files, state, rstate;
    private RoutingCfg cfg;
    private List<RoutingCfg.Node> nodes;
    private JSONObject cats;
    private LinearLayout root;
    private TextView liveView;
    private volatile String dlText = "";
    private volatile boolean dlBusy;
    private boolean resumed;
    private String downloadResult;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        files = getFilesDir();
        state = new File(files, "state");
        rstate = new File(files, "rstate");
        rstate.mkdirs();
        ScrollView sv = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 48, 24, 48);
        sv.addView(root);
        setContentView(sv);
        load();
        render();
        labIntent();
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        load();
        render();
        showDownloadResult();
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        resumed = false;
        super.onPause();
        ui.removeCallbacks(tick);
    }

    private void showDownloadResult() {
        if (downloadResult == null) return;
        Toast.makeText(this, downloadResult, Toast.LENGTH_LONG).show();
        downloadResult = null;
    }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            try {
                JSONObject j = liveStatus();
                if (j != null) {
                    int before = nodes.size();
                    RoutingCfg.cacheNodes(files, j.optJSONArray("exits"));
                    nodes = RoutingCfg.nodes(files);
                    if (nodes.size() != before) render();
                }
                if (liveView != null) liveView.setText(liveText(j));
            } catch (Throwable ignored) { }
            ui.postDelayed(this, 2000);
        }
    };

    private void load() {
        cfg = RoutingCfg.load(state);
        nodes = RoutingCfg.nodes(files);
        try { cats = new JSONObject(Util.read(new File(rstate, "rules-cats.json"))); } catch (Throwable t) { cats = null; }
    }

    private void save() {
        cfg.save(state);
    }

    /** Лаборатория: подмена конфига и запуск скачивания по интенту (в обычной сборке недоступно). */
    private void labIntent() {
        if (!Util.LAB_BUILD) return;
        String r = getIntent().getStringExtra("routing");
        if (r != null) {
            try { java.nio.file.Files.write(RoutingCfg.file(state).toPath(), r.getBytes("UTF-8")); } catch (Throwable ignored) { }
            load();
            render();
        }
        if (getIntent().getBooleanExtra("download", false)) startDownload();
    }

    // ---------------------------------------------------------------- построение экрана

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density); }

    private TextView text(String s, int sp, boolean bold, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private TextView section(String s) {
        TextView t = text(s, 16, true, 0xFF222222);
        t.setPadding(0, dp(22), 0, dp(4));
        return t;
    }

    private Button small(String s, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(s);
        b.setAllCaps(false);
        b.setMinWidth(0);
        b.setMinimumWidth(0);
        b.setPadding(dp(10), 0, dp(10), 0);
        b.setOnClickListener(l);
        return b;
    }

    private void render() {
        root.removeAllViews();
        root.addView(text("Маршрутизация", 20, true, 0xFF000000));

        LinearLayout modes = new LinearLayout(this);
        modes.setOrientation(LinearLayout.HORIZONTAL);
        String[][] ms = {{"auto", "Авто"}, {"priority", "Приоритеты"}, {"rules", "По спискам"}};
        for (String[] m : ms) {
            boolean on = cfg.mode.equals(m[0]);
            Button b = new Button(this);
            b.setAllCaps(false);
            b.setText(m[1]);
            b.setTypeface(on ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
            b.setTextColor(on ? GREEN : 0xFF222222);
            b.setOnClickListener(v -> { cfg.mode = m[0]; save(); render(); });
            modes.addView(b, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        }
        root.addView(modes);
        String d = cfg.mode.equals("auto")
                ? "Телефон сам выбирает выход с наименьшей задержкой. Узел, который у вас недоступен из-за блокировок, тоже может оказаться «ближайшим»: тогда задайте приоритеты."
                : cfg.mode.equals("priority")
                ? "Телефон подключается к самому верхнему из доступных выходов; если он недоступен, к следующему. Возврат на более высокий — после 15 с стабильной связи."
                : "Приоритеты выходов плюс отдельные узлы для разных списков: например российский трафик мимо VPN, а YouTube через выбранный узел. Побеждает первое совпадение: сначала свои записи, затем правила сверху вниз.";
        root.addView(text(d, 13, false, GREY));

        if (!cfg.mode.equals("auto")) renderPriority();
        if (cfg.mode.equals("rules")) {
            renderFiles();
            renderRules();
            renderManual();
            root.addView(text("«Мимо VPN» работает по IP-подсетям (например, список RU) и применяется при подключении. Правила по доменам узнают адрес из DNS-ответов, прошедших через VPN: DNS-over-HTTPS и «частный DNS» браузера их скрывают. Если узел для правила недоступен, трафик идёт через основной выход.", 11, false, GREY));
        }
        liveView = text("", 12, false, 0xFF444444);
        liveView.setTypeface(Typeface.MONOSPACE);
        liveView.setPadding(0, dp(18), 0, 0);
        root.addView(liveView);
        liveView.setText(liveText(liveStatus()));
    }

    // ---------------------------------------------------------------- приоритеты

    private String nameOf(String hex) {
        for (RoutingCfg.Node n : nodes) if (n.d.equals(hex)) return TopologyView.shortName(n.n);
        return hex.substring(0, 8);
    }

    /** Все известные выходы: сначала названные в списке приоритетов (по порядку), затем остальные. */
    private List<String> orderedNodes() {
        List<String> out = new ArrayList<>();
        for (String p : cfg.priority) for (RoutingCfg.Node n : nodes) if (n.d.equals(p) && !out.contains(p)) out.add(p);
        for (RoutingCfg.Node n : nodes) if (!out.contains(n.d)) out.add(n.d);
        return out;
    }

    private void renderPriority() {
        root.addView(section("Приоритет выходов"));
        List<String> ord = orderedNodes();
        if (ord.isEmpty()) {
            root.addView(text("Список выходов появится после первого подключения.", 13, false, GREY));
            return;
        }
        for (int i = 0; i < ord.size(); i++) {
            final int k = i;
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            TextView t = text((i + 1) + ".  " + nameOf(ord.get(i)), 15, i == 0, 0xFF222222);
            row.addView(t, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            Button up = small("↑", v -> move(ord, k, -1));
            Button dn = small("↓", v -> move(ord, k, 1));
            up.setEnabled(i > 0);
            dn.setEnabled(i < ord.size() - 1);
            row.addView(up);
            row.addView(dn);
            root.addView(row);
        }
        root.addView(text("Выход, который вы выбрали вручную на главном экране, важнее списка.", 11, false, GREY));
    }

    private void move(List<String> ord, int i, int delta) {
        Collections.swap(ord, i, i + delta);
        cfg.priority.clear();
        cfg.priority.addAll(ord);
        save();
        render();
    }

    // ---------------------------------------------------------------- файлы списков

    private void renderFiles() {
        root.addView(section("Списки"));
        boolean have = RulesFiles.present(files);
        String info = "Не загружены. Источник: runetfreedom/russia-v2ray-rules-dat (обновляется каждые 6 часов), около 90 МБ.";
        if (have) {
            File g1 = new File(RulesFiles.dir(files), "geoip.dat"), g2 = new File(RulesFiles.dir(files), "geosite.dat");
            info = "Загружены: geoip " + (g1.length() >> 20) + " МБ, geosite " + (g2.length() >> 20) + " МБ, "
                    + new SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(new Date(Math.min(g1.lastModified(), g2.lastModified())));
        }
        root.addView(text(dlBusy ? "Загрузка… " + dlText : info, 13, false, 0xFF333333));
        Button b = new Button(this);
        b.setAllCaps(false);
        b.setText(have ? "Обновить списки" : "Скачать списки");
        b.setEnabled(!dlBusy);
        b.setOnClickListener(v -> startDownload());
        root.addView(b);
    }

    private void startDownload() {
        if (dlBusy) return;
        dlBusy = true;
        dlText = "";
        render();
        new Thread(() -> {
            String err = RulesFiles.download(files, t -> { dlText = t; ui.post(() -> {
                if (resumed && !isFinishing() && !isDestroyed() && dlBusy) render();
            }); });
            if (err.isEmpty()) {
                try { Native.runVpn("rules-list --state " + rstate.getAbsolutePath(), rstate.getAbsolutePath()); } catch (Throwable t) { err = "разбор: " + t; }
            }
            final String e = err;
            ui.post(() -> {
                dlBusy = false;
                if (isFinishing() || isDestroyed()) return;
                downloadResult = e.isEmpty() ? "Списки загружены" : "Не удалось: " + e;
                if (!resumed) return;
                load();
                render();
                showDownloadResult();
            });
        }, "rawg-rules-dl").start();
    }

    // ---------------------------------------------------------------- правила

    private String actionText(String a) {
        if (a.equals("default")) return "основной выход";
        if (a.equals("direct")) return "мимо VPN";
        if (a.startsWith("exit:")) return "через " + nameOf(a.substring(5));
        return a;
    }

    private interface Pick { void on(String action); }

    private void pickAction(boolean allowDirect, Pick cb) {
        List<String> acts = new ArrayList<>(), labels = new ArrayList<>();
        acts.add("default");
        labels.add("Основной выход (по приоритетам)");
        if (allowDirect) { acts.add("direct"); labels.add("Мимо VPN"); }
        for (RoutingCfg.Node n : nodes) { acts.add("exit:" + n.d); labels.add("Через " + TopologyView.shortName(n.n)); }
        new AlertDialog.Builder(this).setTitle("Куда отправлять")
                .setItems(labels.toArray(new String[0]), (dlg, w) -> cb.on(acts.get(w)))
                .setNegativeButton("Отмена", null).show();
    }

    private static String hint(String type, String name) {
        switch (type + ":" + name.toUpperCase(Locale.ROOT)) {
            case "geoip:RU": return "Россия";
            case "geoip:BY": return "Беларусь";
            case "geoip:PRIVATE": return "локальные сети";
            case "geoip:RU-BLOCKED": return "заблокированные в РФ";
            case "geoip:RU-WHITELIST": return "белый список РФ";
            case "geosite:RU-BLOCKED": return "заблокированные в РФ";
            case "geosite:CATEGORY-RU": return "российские сайты";
            case "geosite:YOUTUBE": return "YouTube";
            case "geosite:GOOGLE": return "Google";
            case "geosite:TELEGRAM": return "Telegram";
            case "geosite:CATEGORY-ADS-ALL": return "реклама";
            default: return "";
        }
    }

    private void renderRules() {
        root.addView(section("Правила по спискам"));
        if (cfg.rules.isEmpty()) root.addView(text("Правил нет: весь трафик идёт через основной выход.", 13, false, GREY));
        for (int i = 0; i < cfg.rules.size(); i++) {
            final int k = i;
            final RoutingCfg.Rule r = cfg.rules.get(i);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            String h = hint(r.type, r.name);
            TextView t = text((r.type.equals("geoip") ? "IP " : "сайты ") + r.name + (h.isEmpty() ? "" : " (" + h + ")") + "\n→ " + actionText(r.action), 14, false, 0xFF222222);
            t.setPadding(0, dp(8), 0, dp(8));
            t.setOnClickListener(v -> pickAction(r.type.equals("geoip"), a -> { r.action = a; save(); render(); }));
            row.addView(t, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            Button up = small("↑", v -> { Collections.swap(cfg.rules, k, k - 1); save(); render(); });
            Button dn = small("↓", v -> { Collections.swap(cfg.rules, k, k + 1); save(); render(); });
            up.setEnabled(i > 0);
            dn.setEnabled(i < cfg.rules.size() - 1);
            row.addView(up);
            row.addView(dn);
            row.addView(small("✕", v -> { cfg.rules.remove(k); save(); render(); }));
            root.addView(row);
        }
        LinearLayout acts = new LinearLayout(this);
        acts.setOrientation(LinearLayout.HORIZONTAL);
        Button add = new Button(this);
        add.setAllCaps(false);
        add.setText("Добавить список");
        add.setOnClickListener(v -> addRuleDialog());
        acts.addView(add, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        Button pre = new Button(this);
        pre.setAllCaps(false);
        pre.setText("Шаблоны");
        pre.setOnClickListener(v -> presets());
        acts.addView(pre, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        root.addView(acts);
    }

    private void putRule(String type, String name, String action) {
        for (RoutingCfg.Rule r : cfg.rules) if (r.type.equals(type) && r.name.equalsIgnoreCase(name)) { r.action = action; return; }
        if (cfg.rules.size() < RoutingCfg.MAX_RULES) cfg.rules.add(new RoutingCfg.Rule(type, name, action));
    }

    private void presets() {
        if (!hasCats()) { Toast.makeText(this, "Сначала скачайте списки", Toast.LENGTH_SHORT).show(); return; }
        String[] items = {"Россия — мимо VPN", "Заблокированное в РФ — через выбранный узел"};
        new AlertDialog.Builder(this).setTitle("Шаблоны").setItems(items, (dlg, w) -> {
            if (w == 0) {
                putRule("geoip", "RU", "direct");
                save();
                render();
            } else {
                pickAction(false, a -> {
                    putRule("geosite", "RU-BLOCKED", a);
                    putRule("geoip", "RU-BLOCKED", a);
                    save();
                    render();
                });
            }
        }).setNegativeButton("Отмена", null).show();
    }

    private boolean hasCats() {
        return cats != null && ((cats.optJSONArray("geoip") != null && cats.optJSONArray("geoip").length() > 0)
                || (cats.optJSONArray("geosite") != null && cats.optJSONArray("geosite").length() > 0));
    }

    private void addRuleDialog() {
        if (!hasCats()) { Toast.makeText(this, "Сначала скачайте списки", Toast.LENGTH_SHORT).show(); return; }
        final String[] type = {"geosite"};
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), 0);
        LinearLayout tg = new LinearLayout(this);
        tg.setOrientation(LinearLayout.HORIZONTAL);
        Button bs = new Button(this), bi = new Button(this);
        bs.setAllCaps(false);
        bi.setAllCaps(false);
        bs.setText("Сайты");
        bi.setText("Подсети (IP)");
        tg.addView(bs, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        tg.addView(bi, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        box.addView(tg);
        EditText q = new EditText(this);
        q.setHint("поиск: youtube, ru, telegram…");
        q.setSingleLine(true);
        q.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        box.addView(q);
        ListView lv = new ListView(this);
        box.addView(lv, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(320)));
        final List<String> names = new ArrayList<>(), shown = new ArrayList<>();
        ArrayAdapter<String> ad = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, shown);
        lv.setAdapter(ad);
        Runnable refill = () -> {
            names.clear();
            shown.clear();
            JSONArray a = cats.optJSONArray(type[0]);
            String f = q.getText().toString().trim().toUpperCase(Locale.ROOT);
            List<Object[]> hit = new ArrayList<>();
            for (int i = 0; a != null && i < a.length(); i++) {
                JSONArray e = a.optJSONArray(i);
                if (e == null) continue;
                String n = e.optString(0);
                String h = hint(type[0], n);
                if (!f.isEmpty() && !n.toUpperCase(Locale.ROOT).contains(f) && !h.toUpperCase(Locale.ROOT).contains(f)) continue;
                int rank = n.toUpperCase(Locale.ROOT).startsWith(f) ? 0 : 1;
                if (!h.isEmpty()) rank -= 2;
                hit.add(new Object[]{n, e.optLong(1), rank});
            }
            Collections.sort(hit, (x, y) -> (int) x[2] != (int) y[2] ? Integer.compare((int) x[2], (int) y[2]) : Long.compare((long) y[1], (long) x[1]));
            for (int i = 0; i < hit.size() && i < 80; i++) {
                String n = (String) hit.get(i)[0];
                long sz = (long) hit.get(i)[1];
                String h = hint(type[0], n);
                names.add(n);
                String big = type[0].equals("geosite") && sz > 9_500_000 ? "  ⚠ слишком велик, будет пропущен" : "";
                shown.add(n + (h.isEmpty() ? "" : "  ·  " + h) + "\n" + (sz >= (1 << 20) ? (sz >> 20) + " МБ" : (sz >> 10) + " КБ") + big);
            }
            ad.notifyDataSetChanged();
        };
        bs.setOnClickListener(v -> { type[0] = "geosite"; bs.setTypeface(Typeface.DEFAULT_BOLD); bi.setTypeface(Typeface.DEFAULT); refill.run(); });
        bi.setOnClickListener(v -> { type[0] = "geoip"; bi.setTypeface(Typeface.DEFAULT_BOLD); bs.setTypeface(Typeface.DEFAULT); refill.run(); });
        bs.setTypeface(Typeface.DEFAULT_BOLD);
        q.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) { }
            @Override public void afterTextChanged(Editable e) { refill.run(); }
        });
        refill.run();
        AlertDialog dlg = new AlertDialog.Builder(this).setTitle("Добавить список").setView(box).setNegativeButton("Отмена", null).create();
        lv.setOnItemClickListener((p, v, pos, id) -> {
            String name = names.get(pos), t = type[0];
            dlg.dismiss();
            pickAction(t.equals("geoip"), a -> { putRule(t, name, a); save(); render(); });
        });
        dlg.show();
    }

    // ---------------------------------------------------------------- ручные записи

    private void renderManual() {
        root.addView(section("Свои записи (высший приоритет)"));
        root.addView(text("Домены, IP и подсети. Действуют раньше любых списков.", 12, false, GREY));
        for (int i = 0; i < cfg.manual.size(); i++) {
            final int k = i;
            final RoutingCfg.Manual m = cfg.manual.get(i);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            TextView t = text(m.value + "  → " + actionText(m.action), 14, false, 0xFF222222);
            t.setPadding(0, dp(6), 0, dp(6));
            t.setOnClickListener(v -> pickAction(RoutingCfg.isIp(m.value), a -> { m.action = a; save(); render(); }));
            row.addView(t, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            row.addView(small("✕", v -> { cfg.manual.remove(k); save(); render(); }));
            root.addView(row);
        }
        Button add = new Button(this);
        add.setAllCaps(false);
        add.setText("Добавить записи");
        add.setOnClickListener(v -> addManualDialog());
        root.addView(add);
    }

    private void addManualDialog() {
        EditText e = new EditText(this);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setMinLines(5);
        e.setGravity(Gravity.TOP);
        e.setTextSize(13);
        e.setHint("по одной в строке:\nexample.org\nfull:api.example.org\nkeyword:tracker\n203.0.113.7\n10.0.0.0/8");
        new AlertDialog.Builder(this).setTitle("Свои записи").setView(e)
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Далее", (dlg, w) -> {
                    List<String> lines = new ArrayList<>();
                    boolean allIp = true;
                    for (String l : e.getText().toString().split("\n")) {
                        String s = l.trim();
                        if (s.isEmpty() || s.startsWith("#") || s.length() > 253) continue;
                        lines.add(s);
                        if (!RoutingCfg.isIp(s)) allIp = false;
                    }
                    if (lines.isEmpty()) return;
                    pickAction(allIp, a -> {
                        for (String s : lines) {
                            if (cfg.manual.size() >= RoutingCfg.MAX_MANUAL) break;
                            boolean dup = false;
                            for (RoutingCfg.Manual m : cfg.manual) if (m.value.equalsIgnoreCase(s)) { m.action = a; dup = true; }
                            if (!dup) cfg.manual.add(new RoutingCfg.Manual(s, a));
                        }
                        save();
                        render();
                    });
                }).show();
    }

    // ---------------------------------------------------------------- состояние

    private JSONObject liveStatus() {
        try {
            if (!"up".equals(RawgVpnService.phase) && !"connecting".equals(RawgVpnService.phase)) return null;
            String js = Util.read(new File(state, "status.json"));
            return js.isEmpty() ? null : new JSONObject(js);
        } catch (Throwable t) {
            return null;
        }
    }

    private String liveText(JSONObject j) {
        if (j == null) return "VPN выключен: настройки вступят в силу при подключении.";
        StringBuilder s = new StringBuilder();
        JSONObject cur = j.optJSONObject("current");
        s.append("Основной выход: ").append(cur == null ? "— (ищу)" : TopologyView.shortName(cur.optString("n"))).append('\n');
        JSONObject r = j.optJSONObject("routing");
        if (r != null && r.optBoolean("on")) {
            JSONArray ex = r.optJSONArray("extras");
            for (int i = 0; ex != null && i < ex.length(); i++) {
                JSONObject x = ex.optJSONObject(i);
                s.append("Доп. выход: ").append(TopologyView.shortName(x.optString("n"))).append(", ответ ").append(x.optLong("age_s")).append(" с назад\n");
            }
            JSONArray pend = r.optJSONArray("pending");
            if (pend != null && pend.length() > 0) s.append("Поднимаю доп. выходов: ").append(pend.length()).append('\n');
            s.append("Пакетов по правилам: ").append(r.optLong("extra_pkts")).append(", ушли через основной вместо правила: ").append(r.optLong("fallback_pkts") + r.optLong("direct_fallback_pkts")).append('\n');
            JSONObject rep = r.optJSONObject("report");
            JSONArray w = rep == null ? null : rep.optJSONArray("warnings");
            for (int i = 0; w != null && i < w.length() && i < 6; i++) s.append("⚠ ").append(w.optString(i)).append('\n');
        }
        String applied = getSharedPreferences("p", MODE_PRIVATE).getString("routing_sig", "");
        if (!cfg.directSig().equals(applied)) s.append("⚠ Правила «мимо VPN» изменились: отключите и снова включите VPN.\n");
        return s.toString().trim();
    }
}
