package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputType;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextWatcher;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.Switch;
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
 * Экран «Маршрутизация». Два режима: «Весь трафик через выход» и «По правилам» (сайты, подсети и списки geoip/geosite проекта
 * runetfreedom идут через другой выход или мимо VPN, остальное - через выход по умолчанию). Выход по умолчанию выбирается на главном
 * экране или автоматически; рейтинга и приоритетов выходов нет. Порядок проверки правил показывается отдельно и не связан с выбором
 * выхода. Изменения сохраняются сразу в state/routing.json; запущенный клиент подхватывает их за секунду. Исключение - правила
 * «мимо VPN»: они задают исключённые маршруты туннеля и применяются при следующем подключении.
 */
public class RoutingActivity extends Activity {
    static final String EXTRA_TARGET = "routing_target", EXTRA_NAME = "routing_name";
    private static final int GREEN = 0xFF1F7A3A, GREY = 0xFF555555, TEXT = 0xFF222222, WARN = 0xFF8A4B00;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private File files, state, rstate;
    private RoutingCfg cfg;
    private RoutingStatus st;
    private RoutingLabels lb;
    private List<RoutingCfg.Node> nodes;
    private List<RoutingIssues.Issue> issues = new ArrayList<>();
    private JSONObject cats;
    private ScrollView sv;
    private LinearLayout root, out;
    private boolean showPresetRules;
    private TextView detailsView;
    private volatile String dlText = "";
    private volatile boolean dlBusy, importBusy;
    private long importTried = -1;
    private boolean resumed, showDetails;
    private String downloadResult, renderSig = "";
    private String target = "", targetName = "";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        files = getFilesDir();
        state = new File(files, "state");
        String chosen = getIntent().getStringExtra(EXTRA_TARGET);
        if (chosen != null && chosen.matches("[0-9a-fA-F]{32}")) {
            target = chosen.toLowerCase(Locale.ROOT);
            targetName = RightsEditor.clip(getIntent().getStringExtra(EXTRA_NAME));
        }
        rstate = new File(files, "rstate");
        rstate.mkdirs();
        sv = new ScrollView(this);
        sv.setFillViewport(true);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(24), dp(16), dp(32));
        out = root;
        sv.setBackgroundColor(Ui.BG);
        sv.addView(root);
        setContentView(sv);
        RoutingCfg.migrateLegacy(state);
        RoutingCfg.ensureDefaults(state);
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
                RoutingStatus s = RoutingStatus.read(state);
                if (s.haveData) {
                    int before = nodes.size();
                    RoutingCfg.cacheNodes(files, s.exitsRaw);
                    nodes = RoutingCfg.nodes(files);
                    if (nodes.size() != before) lb = new RoutingLabels(nodes);
                }
                st = s;
                issues = collectIssues();
                if (!signature().equals(renderSig)) render();
                else if (detailsView != null) detailsView.setText(detailsText());
            } catch (Throwable ignored) { }
            ui.postDelayed(this, 2000);
        }
    };

    private void load() {
        cfg = RoutingCfg.load(state);
        nodes = RoutingCfg.nodes(files);
        lb = new RoutingLabels(nodes);
        try { cats = new JSONObject(Util.read(new File(rstate, "rules-cats.json"))); } catch (Throwable t) { cats = null; }
        st = RoutingStatus.read(state);
        issues = collectIssues();
    }

    /** Сохраняет настройки; при отказе показывает причину. */
    private void save() {
        String err = cfg.save(state);
        if (!err.isEmpty()) Toast.makeText(this, err, Toast.LENGTH_LONG).show();
    }

    private void saveAndRender() {
        save();
        render();
    }

    /** Лаборатория: подмена конфига и запуск скачивания по интенту (в обычной сборке недоступно). */
    private void labIntent() {
        if (!Util.LAB_BUILD) return;
        String r = getIntent().getStringExtra("routing");
        if (r != null) {
            try { java.nio.file.Files.write(RoutingCfg.file(state).toPath(), r.getBytes("UTF-8")); } catch (Throwable ignored) { }
            RoutingCfg.migrateLegacy(state);
            load();
            render();
        }
        if (getIntent().getBooleanExtra("download", false)) startDownload();
    }

    private List<RoutingIssues.Issue> collectIssues() {
        return RoutingIssues.collect(cfg, st, lb, RulesFiles.present(files), cats,
                getSharedPreferences("p", MODE_PRIVATE).getString("routing_sig", ""));
    }

    /** Что определяет вид экрана: при тике перерисовываем только если это изменилось (иначе прокрутка и нажатия сбивались бы). */
    private String signature() {
        StringBuilder s = new StringBuilder();
        s.append(st.active).append(st.error).append(st.currentDest).append(st.selectedDest).append(nodes.size()).append(dlBusy).append(importBusy);
        for (RoutingIssues.Issue i : issues) s.append('|').append(i.text);
        return s.toString();
    }

    // ---------------------------------------------------------------- построение экрана

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }

    private TextView text(String s, int sp, boolean bold, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(Ui.ink(this, color));
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private TextView section(String s) {
        TextView t = text(s, 17, true, 0xFF111111);
        t.setPadding(0, dp(24), 0, dp(4));
        if (Build.VERSION.SDK_INT >= 28) t.setAccessibilityHeading(true);
        return t;
    }

    private TextView note(String s) {
        TextView t = text(s, 13, false, GREY);
        t.setPadding(0, dp(2), 0, dp(4));
        return t;
    }

    private Button button(String s, View.OnClickListener l) {
        Button b = Ui.secondary(this, s, l);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(8);
        b.setLayoutParams(lp);
        return b;
    }

    private LinearLayout.LayoutParams weight() {
        return new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1);
    }

    private void render() {
        int scroll = sv.getScrollY();
        st = RoutingStatus.read(state);
        issues = collectIssues();
        root.removeAllViews();
        out = root;
        detailsView = null;
        if (target.isEmpty()) out.addView(NodeTabs.bar(this, NodeTabs.ROUTING));
        TextView title = text(target.isEmpty() ? "Маршрутизация" : "Маршруты через " + (targetName.isEmpty() ? lb.nameOf(target) : targetName), 24, true, Ui.TEXT);
        title.setPadding(0, dp(8), 0, 0);
        if (Build.VERSION.SDK_INT >= 28) title.setAccessibilityHeading(true);
        out.addView(title);
        renderLegacyBanner();
        if (target.isEmpty()) {
            renderPresets();
            renderExitFilter();
            renderIssues();
            beginCard("Свои правила", "Ваши адреса, домены и списки проверяются раньше правил режима, поэтому могут его переопределить. Сначала идут «Свои адреса и домены» сверху вниз, затем «Списки» сверху вниз; "
                    + "действует первое совпавшее правило, иначе трафик идёт по режиму. Подсети «Мимо VPN» система исключает из туннеля при подключении, поэтому они срабатывают раньше остальных. "
                    + RoutingLabels.DOMAIN_NOTE);
            renderManual();
            renderLists();
            out.addView(button("Импорт правил JSON…", v -> importDialog("")));
            out.addView(button("Приложения мимо VPN…", v -> startActivity(new android.content.Intent(this, AppsActivity.class))));
            if (RoutingPresets.find(cfg.preset()) != null) {
                out.addView(button(showPresetRules ? "Скрыть правила режима" : "Показать правила режима", v -> { showPresetRules = !showPresetRules; render(); }));
            }
            endCard();
            renderFiles();
        } else {
            out.addView(note("Здесь только правила с выходом через эту ноду. Другие правила телефона сохраняются."));
            if (!cfg.mode.equals(RoutingCfg.MODE_RULES)) out.addView(button("Включить маршрутизацию по правилам", v -> { cfg.mode = RoutingCfg.MODE_RULES; saveAndRender(); }));
            out.addView(button("Все правила телефона", v -> startActivity(new android.content.Intent(this, RoutingActivity.class))));
            out.addView(button("Импорт правил JSON…", v -> importDialog("")));
            renderIssues();
            renderManual();
            renderLists();
            renderFiles();
        }
        renderDetails();
        renderSig = signature();
        sv.post(() -> sv.scrollTo(0, scroll));
    }

    // ---------------------------------------------------------------- карточки

    private void beginCard(String title, String help) {
        LinearLayout c = Ui.card(this);
        c.addView(Ui.titleWithHelp(this, title, help));
        root.addView(c, Ui.cardParams(this));
        out = c;
    }

    private void endCard() { out = root; }

    // ---------------------------------------------------------------- режимы (пресеты)

    private void renderPresets() {
        beginCard("Режим", "Готовые режимы маршрутизации. Выбранный режим записывает свои правила; ваши собственные правила остаются и работают поверх него. "
                + "Изменения вступают в силу при следующем включении VPN.");
        String cur = cfg.preset();
        for (RoutingPresets.Preset p : RoutingPresets.ALL) {
            boolean on = p.id.equals(cur);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(12), dp(6), dp(8), dp(6));
            row.setMinimumHeight(dp(52));
            int accent = p.unsafe ? Ui.RED : Ui.GREEN;
            row.setBackground(on ? Ui.roundStroke(0xFF1E2A22, accent, 12, this) : Ui.roundStroke(Ui.CARD_HI, Ui.STROKE, 12, this));
            TextView dot = Ui.text(this, on ? "●" : "○", 18, on ? accent : Ui.MUTED, false);
            dot.setPadding(0, 0, dp(10), 0);
            row.addView(dot);
            TextView name = Ui.text(this, p.title, 15, p.unsafe ? Ui.RED : Ui.TEXT, on);
            row.addView(name, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            row.addView(Ui.help(this, p.title, p.help), Ui.helpParams(this));
            row.setClickable(true);
            row.setOnClickListener(v -> { Ui.tick(v); if (!on) choosePreset(p); });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.topMargin = dp(8);
            out.addView(row, lp);
        }
        if (cur.isEmpty() || RoutingPresets.find(cur) == null) out.addView(note("Сейчас правила настроены вручную."));
        if (RoutingPresets.ALL_DIRECT.equals(cur)) {
            TextView w = text("⚠ Трафик не защищён: идёт напрямую, мимо VPN", 13, true, Ui.RED);
            w.setPadding(0, dp(10), 0, 0);
            out.addView(w);
        }
        out.addView(button("Сбросить к умолчанию", v -> new AlertDialog.Builder(this).setTitle("Сбросить маршрутизацию?")
                .setMessage("Режим «Обход только заблокированного», выбор выходов без «Россия». Свои правила будут удалены.")
                .setPositiveButton("Сбросить", (d, w2) -> {
                    cfg.rules.clear(); cfg.manual.clear();
                    RoutingPresets.apply(cfg, RoutingPresets.DEFAULT);
                    cfg.setExitFilter(true, java.util.Arrays.asList(RoutingPresets.DEFAULT_EXCLUDE));
                    saveAndRender();
                }).setNegativeButton("Отмена", null).show()));
        endCard();
    }

    private void choosePreset(RoutingPresets.Preset p) {
        Runnable go = () -> {
            RoutingPresets.apply(cfg, p.id);
            saveAndRender();
            boolean needLists = p.id.equals(RoutingPresets.BLOCKED) || p.id.equals(RoutingPresets.RU_DIRECT);
            Toast.makeText(this, needLists && !RulesFiles.present(files) ? "Режим выбран. Нужны файлы списков: скачайте их ниже" : "Режим выбран. Вступит в силу при следующем включении VPN", Toast.LENGTH_LONG).show();
        };
        if (!p.unsafe) { go.run(); return; }
        new AlertDialog.Builder(this).setTitle("Всё напрямую?")
                .setMessage("Трафик НЕ будет защищён: он пойдёт мимо VPN, сайты и провайдер увидят ваш настоящий адрес. Включайте только осознанно.")
                .setPositiveButton("Всё напрямую", (d, w) -> go.run())
                .setNegativeButton("Отмена", null).show();
    }

    // ---------------------------------------------------------------- выбор выходов

    private void renderExitFilter() {
        beginCard("Выбор выходов", "Автовыбор выхода пропускает ноды по имени: «не содержит» исключает ноды, в имени которых есть любое из слов (по умолчанию «Россия»), "
                + "«содержит» оставляет только такие. Регистр не важен. Нода, выбранная вами тапом на главном экране, фильтром не отключается. "
                + "Если фильтр отсёк все выходы, работа продолжится через остальные, а не остановится.");
        LinearLayout seg = new LinearLayout(this);
        seg.setOrientation(LinearLayout.HORIZONTAL);
        boolean ex = cfg.filterExclude();
        Button a = segButton("Имя не содержит", ex), b = segButton("Имя содержит", !ex);
        a.setOnClickListener(v -> { Ui.tick(v); cfg.setExitFilter(true, cfg.filterWords()); saveAndRender(); });
        b.setOnClickListener(v -> { Ui.tick(v); cfg.setExitFilter(false, cfg.filterWords()); saveAndRender(); });
        LinearLayout.LayoutParams l1 = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        l1.rightMargin = dp(8);
        seg.addView(a, l1);
        seg.addView(b, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        LinearLayout.LayoutParams sl = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        sl.topMargin = dp(10);
        out.addView(seg, sl);
        List<String> words = cfg.filterWords();
        TextView w = text(words.isEmpty() ? "Слов нет — фильтр выключен" : String.join(", ", words), 15, !words.isEmpty(), words.isEmpty() ? GREY : Ui.TEXT);
        w.setPadding(0, dp(10), 0, dp(4));
        out.addView(w);
        out.addView(button("Изменить слова", v -> editWords(words)));
        String now;
        if (st.error) now = "VPN остановлен из-за ошибки";
        else if (!st.active) now = "";
        else if (st.currentDest.isEmpty()) now = "Выход ещё ищется";
        else now = "Сейчас: " + lb.nameOf(st.currentDest);
        if (!now.isEmpty()) out.addView(note(now));
        endCard();
    }

    private Button segButton(String s, boolean on) {
        Button b = on ? Ui.primary(this, s, null) : Ui.secondary(this, s, null);
        b.setTextSize(13);
        return b;
    }

    private void editWords(List<String> current) {
        EditText e = new EditText(this);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setSingleLine(true);
        e.setHint("россия, russia");
        e.setText(String.join(", ", current));
        e.setSelection(e.getText().length());
        new AlertDialog.Builder(this).setTitle("Слова в имени ноды (через запятую)").setView(e)
                .setPositiveButton("Сохранить", (d, w) -> {
                    List<String> ws = new ArrayList<>();
                    for (String x : e.getText().toString().split("[,;\\n]")) { String t = x.trim(); if (!t.isEmpty()) ws.add(t); }
                    cfg.setExitFilter(cfg.filterExclude(), ws);
                    saveAndRender();
                }).setNegativeButton("Отмена", null).show();
    }

    // ---------------------------------------------------------------- шаблоны и совместимый импорт JSON

    private void importDialog(String prefill) {
        EditText e = new EditText(this);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setMinLines(6);
        e.setGravity(Gravity.TOP);
        e.setTextSize(12);
        e.setHint("[{\"outboundTag\":\"direct\",\"domain\":[\"geosite:category-ru\"]}, …]");
        e.setText(prefill);
        AlertDialog dlg = new AlertDialog.Builder(this).setTitle("Импорт правил JSON").setView(e)
                .setNeutralButton("Вставить", null)
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Далее", null).create();
        dlg.setOnShowListener(x -> {
            dlg.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                android.content.ClipboardManager cb = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                android.content.ClipData d = cb.getPrimaryClip();
                if (d != null && d.getItemCount() > 0 && d.getItemAt(0).getText() != null) e.setText(d.getItemAt(0).getText());
            });
            dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                try {
                    RoutingImport.Result r = RoutingImport.parse(e.getText().toString());
                    dlg.dismiss();
                    confirmImport(r, "Импорт правил", "");
                } catch (Exception ex) {
                    e.setError("Не JSON-массив правил: " + ex.getMessage());
                }
            });
        });
        dlg.show();
    }

    private void confirmImport(RoutingImport.Result r, String title, String intro) {
        final RoutingImport.Result imported = target.isEmpty() ? r : RoutingImport.forTarget(r, target);
        r = imported;
        StringBuilder m = new StringBuilder();
        if (!intro.isEmpty()) m.append(intro).append("\n\n");
        m.append("Будет перенесено записей: ").append(r.count()).append(" (списки: ").append(r.rules.size()).append(", свои адреса и домены: ").append(r.manual.size()).append(")\n");
        m.append("\nПорядок KnotHop: свои записи перед списками; подсети «напрямую» исключаются из VPN системно. Порядок исходного JSON может отличаться.\n");
        if (!target.isEmpty()) m.append("\nВыход для добавляемых правил: ").append(targetName.isEmpty() ? lb.nameOf(target) : targetName).append(". Правила direct относятся ко всему телефону и здесь не импортируются.\n");
        int conflicts = RoutingImport.conflicts(cfg, r);
        if (conflicts > 0) m.append("\nБудет переназначено существующих правил: ").append(conflicts).append(". Их прежние действия заменятся.\n");
        if (r.siteDirect > 0) m.append("\nПравил для сайтов «мимо VPN»: ").append(r.siteDirect).append(". Мимо туннеля работают только подсети, трафик сайтов пойдёт через выход по умолчанию.\n");
        if (!r.skipped.isEmpty()) {
            m.append("\nПропущено: ").append(r.skipped.size()).append('\n');
            for (int i = 0; i < Math.min(8, r.skipped.size()); i++) m.append("• ").append(r.skipped.get(i)).append('\n');
        }
        AlertDialog.Builder b = new AlertDialog.Builder(this).setTitle(title).setMessage(m.toString().trim()).setNegativeButton("Отмена", null);
        if (r.count() > 0) {
            b.setPositiveButton(conflicts > 0 ? "Переназначить и добавить" : "Добавить", (d, w) -> {
                int n = RoutingImport.apply(cfg, imported);
                saveAndRender();
                String extra = RulesFiles.present(files) || !needsLists(imported) ? "" : ". Потяните главный экран вниз, чтобы загрузить геоданные";
                Toast.makeText(this, "Добавлено записей: " + n + extra, Toast.LENGTH_LONG).show();
            });
        }
        b.show();
    }

    private static boolean needsLists(RoutingImport.Result r) { return !r.rules.isEmpty(); }

    private boolean hasDirect() {
        for (RoutingCfg.Rule r : cfg.rules) if (r.enabled && r.action.equals("direct")) return true;
        for (RoutingCfg.Manual m : cfg.manual) if (m.enabled && m.action.equals("direct")) return true;
        return false;
    }

    // ---------------------------------------------------------------- миграция рейтинга

    private void renderLegacyBanner() {
        JSONObject lg = cfg.unackedLegacy();
        if (lg == null) return;
        int n = cfg.legacyCount(lg);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(12), dp(8), dp(12), dp(8));
        box.setBackgroundColor(Ui.warnBg(this));
        box.addView(text("Приоритеты выходов отключены", 15, true, WARN));
        box.addView(text("Раньше порядок " + n + " выходов в списке влиял на выбор. Теперь выход по умолчанию выбирается на главном экране или автоматически, "
                + "а правила и их порядок настраиваются отдельно ниже. Прежний список сохранён в резервной копии в настройках на этом телефоне.", 13, false, TEXT));
        box.addView(button("Понятно", v -> { cfg.ackLegacy(); saveAndRender(); }));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(8);
        out.addView(box, lp);
    }

    // ---------------------------------------------------------------- режим

    // ---------------------------------------------------------------- предупреждения

    private void renderIssues() {
        if (issues.isEmpty()) return;
        out.addView(section("На что обратить внимание"));
        for (RoutingIssues.Issue i : issues) {
            TextView t = text((i.warn ? "⚠ " : "ℹ ") + i.text, 13, false, i.warn ? WARN : GREY);
            t.setPadding(0, dp(3), 0, dp(3));
            out.addView(t);
        }
    }

    // ---------------------------------------------------------------- действия правил

    private interface Pick { void on(String action); }

    private void pickAction(boolean allowDirect, Pick cb) {
        if (!target.isEmpty()) { cfg.mode = RoutingCfg.MODE_RULES; cb.on("exit:" + target); return; }
        List<String> acts = new ArrayList<>(), labels = new ArrayList<>();
        acts.add("default");
        labels.add("Выход по умолчанию");
        for (RoutingCfg.Node n : nodes) {
            acts.add("exit:" + n.d);
            labels.add("Через " + TopologyView.shortName(n.n) + (st.unavailable(n.d) ? " (сейчас недоступен)" : ""));
        }
        if (allowDirect) {
            acts.add("direct");
            labels.add("Мимо VPN ⚠ (напрямую)");
        } else {
            acts.add("");
            labels.add(RoutingLabels.DIRECT_ONLY_IP);
        }
        new AlertDialog.Builder(this).setTitle("Куда отправлять")
                .setItems(labels.toArray(new String[0]), (dlg, w) -> {
                    String a = acts.get(w);
                    if (a.isEmpty()) { Toast.makeText(this, RoutingLabels.DIRECT_ONLY_IP, Toast.LENGTH_SHORT).show(); return; }
                    if (a.equals("direct")) confirmDirect(() -> cb.on(a));
                    else cb.on(a);
                })
                .setNegativeButton("Отмена", null).show();
    }

    private void confirmDirect(Runnable ok) {
        new AlertDialog.Builder(this).setTitle("Пустить мимо VPN?").setMessage(RoutingLabels.DIRECT_WARNING)
                .setPositiveButton("Мимо VPN", (d, w) -> ok.run())
                .setNegativeButton("Отмена", null).show();
    }

    // ---------------------------------------------------------------- строка правила

    private interface Toggle { void set(boolean on); }

    private View ruleRow(String title, String sub, boolean enabled, boolean valid, Toggle toggle, Runnable menu) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(4), 0, dp(4));
        Switch sw = new Switch(this);
        sw.setChecked(enabled);
        sw.setContentDescription((enabled ? "Выключить: " : "Включить: ") + title);
        sw.setOnCheckedChangeListener((v, on) -> toggle.set(on));
        row.addView(sw, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, dp(48)));
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(dp(8), 0, dp(4), 0);
        col.addView(text(title, 15, enabled, enabled ? TEXT : GREY));
        col.addView(text((enabled ? "" : "выключено · ") + (valid ? "" : "не распознано · ") + sub, 13, false, valid ? GREY : WARN));
        col.setOnClickListener(v -> menu.run());
        col.setClickable(true);
        row.addView(col, weight());
        Button more = button("⋯", v -> menu.run());
        more.setMinWidth(dp(48));
        more.setMinimumWidth(dp(48));
        more.setContentDescription("Действия: " + title);
        row.addView(more, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, dp(48)));
        return row;
    }

    private interface Menu { void on(int item); }

    /** Меню действий над записью: изменить выход, порядок проверки, включить/выключить, удалить. */
    private void itemMenu(String title, int index, int size, boolean enabled, Menu cb) {
        List<String> labels = new ArrayList<>();
        List<Integer> ids = new ArrayList<>();
        labels.add("Изменить, куда отправлять…"); ids.add(0);
        if (target.isEmpty() && index > 0) { labels.add("Проверять раньше (выше)"); ids.add(1); }
        if (target.isEmpty() && index < size - 1) { labels.add("Проверять позже (ниже)"); ids.add(2); }
        labels.add(enabled ? "Выключить" : "Включить"); ids.add(3);
        labels.add("Удалить…"); ids.add(4);
        new AlertDialog.Builder(this).setTitle(title)
                .setItems(labels.toArray(new String[0]), (d, w) -> cb.on(ids.get(w)))
                .setNegativeButton("Закрыть", null).show();
    }

    private void confirmDelete(String title, Runnable ok) {
        new AlertDialog.Builder(this).setTitle("Удалить?").setMessage(title)
                .setPositiveButton("Удалить", (d, w) -> ok.run())
                .setNegativeButton("Отмена", null).show();
    }

    private <T> void swap(List<T> l, int i, int j) {
        if (i < 0 || j < 0 || i >= l.size() || j >= l.size()) return;
        Collections.swap(l, i, j);
        saveAndRender();
    }

    // ---------------------------------------------------------------- свои адреса и домены

    private void renderManual() {
        out.addView(section("Свои адреса и домены"));
        for (int i = 0; i < cfg.manual.size(); i++) {
            final int k = i;
            final RoutingCfg.Manual m = cfg.manual.get(i);
            if (!target.isEmpty() && !m.action.equals("exit:" + target)) continue;
            if (target.isEmpty() && !showPresetRules && RoutingPresets.isPresetManual(m)) continue;
            String title = m.value.length() > 60 ? m.value.substring(0, 60) + "…" : m.value;
            String sub = (m.ip() ? "подсеть/IP" : "домен") + " → " + lb.action(m.action);
            out.addView(ruleRow(title, sub, m.enabled, m.valid() && RoutingCfg.cleanManual(m.value) != null, on -> { m.enabled = on; saveAndRender(); }, () ->
                    itemMenu(title, k, cfg.manual.size(), m.enabled, item -> {
                        switch (item) {
                            case 0: pickAction(m.ip(), a -> { m.action = a; saveAndRender(); }); break;
                            case 1: swap(cfg.manual, k, k - 1); break;
                            case 2: swap(cfg.manual, k, k + 1); break;
                            case 3: m.enabled = !m.enabled; saveAndRender(); break;
                            default: confirmDelete(title, () -> { cfg.manual.remove(m); saveAndRender(); });
                        }
                    })));
        }
        out.addView(button("Добавить адреса и домены", v -> addManualDialog()));
    }

    private void addManualDialog() {
        if (cfg.manual.size() >= RoutingCfg.MAX_MANUAL) { Toast.makeText(this, "Не больше " + RoutingCfg.MAX_MANUAL + " записей", Toast.LENGTH_SHORT).show(); return; }
        EditText e = new EditText(this);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setMinLines(5);
        e.setGravity(Gravity.TOP);
        e.setTextSize(14);
        e.setHint("по одной в строке:\nexample.org\nfull:api.example.org\nkeyword:tracker\n203.0.113.7\n10.0.0.0/8");
        e.setContentDescription("Адреса и домены, по одному в строке");
        AlertDialog dlg = new AlertDialog.Builder(this).setTitle("Свои адреса и домены").setView(e)
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Далее", null).create();
        dlg.setCanceledOnTouchOutside(false);
        // непустой ввод не пропадает от случайного нажатия «назад» или «Отмена»: сначала спрашиваем
        Runnable close = dlg::dismiss;
        Runnable tryClose = () -> {
            if (e.getText().toString().trim().isEmpty()) { close.run(); return; }
            new AlertDialog.Builder(this).setTitle("Отбросить введённое?")
                    .setPositiveButton("Отбросить", (d, w) -> close.run())
                    .setNegativeButton("Продолжить ввод", null).show();
        };
        dlg.setOnKeyListener((d, code, ev) -> {
            if (code == KeyEvent.KEYCODE_BACK && ev.getAction() == KeyEvent.ACTION_UP) { tryClose.run(); return true; }
            return code == KeyEvent.KEYCODE_BACK;
        });
        dlg.setOnShowListener(x -> {
            dlg.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(v -> tryClose.run());
            dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                List<String> lines = new ArrayList<>(), bad = new ArrayList<>();
                boolean allIp = true;
                for (String l : e.getText().toString().split("\n")) {
                    String s = l.trim();
                    if (s.isEmpty() || s.startsWith("#")) continue;
                    String ok = RoutingCfg.cleanManual(s);
                    if (ok == null) { bad.add(s.length() > 30 ? s.substring(0, 30) + "…" : s); continue; }
                    lines.add(ok);
                    if (!RoutingCfg.isIp(ok)) allIp = false;
                }
                if (!bad.isEmpty()) {
                    e.setError("Не распознано строк: " + bad.size() + " (например «" + bad.get(0) + "»). Исправьте или удалите их.");
                    return;
                }
                if (lines.isEmpty()) return;
                final boolean ips = allIp;
                dlg.dismiss();
                pickAction(ips, a -> {
                    RoutingImport.Result incoming = new RoutingImport.Result();
                    for (String line : lines) incoming.manual.add(new RoutingCfg.Manual(line, a));
                    int conflicts = RoutingImport.conflicts(cfg, incoming);
                    if (conflicts > 0) {
                        confirmImport(incoming, "Переназначить адреса?", "Эти условия уже используются в других правилах: " + conflicts);
                        return;
                    }
                    int skipped = 0;
                    for (String s : lines) {
                        boolean dup = false;
                        for (RoutingCfg.Manual m : cfg.manual) if (m.value.equalsIgnoreCase(s)) { m.action = a; m.enabled = true; dup = true; }
                        if (dup) continue;
                        if (cfg.manual.size() >= RoutingCfg.MAX_MANUAL) { skipped++; continue; }
                        cfg.manual.add(new RoutingCfg.Manual(s, a));
                    }
                    if (skipped > 0) Toast.makeText(this, "Не добавлено из-за предела " + RoutingCfg.MAX_MANUAL + ": " + skipped, Toast.LENGTH_LONG).show();
                    saveAndRender();
                });
            });
        });
        dlg.show();
    }

    // ---------------------------------------------------------------- списки geoip / geosite

    private void renderLists() {
        out.addView(section("Списки"));
        for (int i = 0; i < cfg.rules.size(); i++) {
            final int k = i;
            final RoutingCfg.Rule r = cfg.rules.get(i);
            if (!target.isEmpty() && !r.action.equals("exit:" + target)) continue;
            if (target.isEmpty() && !showPresetRules && RoutingPresets.isPresetRule(r)) continue;
            String title = RoutingLabels.ruleTitle(r);
            out.addView(ruleRow(title, "→ " + lb.action(r.action), r.enabled, r.valid(), on -> { r.enabled = on; saveAndRender(); }, () ->
                    itemMenu(title, k, cfg.rules.size(), r.enabled, item -> {
                        switch (item) {
                            case 0: pickAction(r.geoip(), a -> { r.action = a; saveAndRender(); }); break;
                            case 1: swap(cfg.rules, k, k - 1); break;
                            case 2: swap(cfg.rules, k, k + 1); break;
                            case 3: r.enabled = !r.enabled; saveAndRender(); break;
                            default: confirmDelete(title, () -> { cfg.rules.remove(r); saveAndRender(); });
                        }
                    })));
        }
        LinearLayout acts = new LinearLayout(this);
        acts.setOrientation(LinearLayout.HORIZONTAL);
        acts.addView(button("Добавить список", v -> addRuleDialog()), weight());
        out.addView(acts);
    }

    private void putRule(String type, String name, String action) {
        for (RoutingCfg.Rule r : cfg.rules) if (r.type.equals(type) && r.name.equalsIgnoreCase(name)) {
            if (!target.isEmpty() && !r.action.equals(action)) {
                new AlertDialog.Builder(this).setTitle("Переназначить правило?")
                        .setMessage(type + ":" + name + " сейчас: " + lb.action(r.action) + ". Перенести на эту ноду?")
                        .setPositiveButton("Переназначить", (d, w) -> { r.action = action; r.enabled = true; saveAndRender(); })
                        .setNegativeButton("Отмена", null).show();
            } else { r.action = action; r.enabled = true; }
            return;
        }
        if (cfg.rules.size() < RoutingCfg.MAX_RULES) cfg.rules.add(new RoutingCfg.Rule(type, name, action));
        else Toast.makeText(this, "Не больше " + RoutingCfg.MAX_RULES + " правил по спискам", Toast.LENGTH_SHORT).show();
    }

    private boolean hasCats() {
        return cats != null && ((cats.optJSONArray("geoip") != null && cats.optJSONArray("geoip").length() > 0)
                || (cats.optJSONArray("geosite") != null && cats.optJSONArray("geosite").length() > 0));
    }

    private void addRuleDialog() {
        if (!hasCats()) { Toast.makeText(this, RulesFiles.present(files) ? "Списки ещё разбираются, повторите через секунду" : "Сначала скачайте списки", Toast.LENGTH_SHORT).show(); return; }
        final String[] type = {"geosite"};
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), 0);
        LinearLayout tg = new LinearLayout(this);
        tg.setOrientation(LinearLayout.HORIZONTAL);
        Button bs = button("Сайты", null), bi = button("Подсети (IP)", null);
        tg.addView(bs, weight());
        tg.addView(bi, weight());
        box.addView(tg);
        EditText q = new EditText(this);
        q.setHint("поиск: youtube, ru, telegram…");
        q.setSingleLine(true);
        q.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        box.addView(q);
        ListView lv = new ListView(this);
        int listH = Math.min(dp(320), getResources().getDisplayMetrics().heightPixels / 2);
        box.addView(lv, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, listH));
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
                String h = RoutingLabels.hint(type[0], n);
                if (!f.isEmpty() && !n.toUpperCase(Locale.ROOT).contains(f) && !h.toUpperCase(Locale.ROOT).contains(f)) continue;
                int rank = n.toUpperCase(Locale.ROOT).startsWith(f) ? 0 : 1;
                if (!h.isEmpty()) rank -= 2;
                hit.add(new Object[]{n, e.optLong(1), rank});
            }
            Collections.sort(hit, (x, y) -> (int) x[2] != (int) y[2] ? Integer.compare((int) x[2], (int) y[2]) : Long.compare((long) y[1], (long) x[1]));
            for (int i = 0; i < hit.size() && i < 80; i++) {
                String n = (String) hit.get(i)[0];
                long sz = (long) hit.get(i)[1];
                String h = RoutingLabels.hint(type[0], n);
                names.add(n);
                String big = type[0].equals("geosite") && sz > 9_500_000 ? "  ⚠ слишком велик, будет пропущен" : "";
                shown.add(n + (h.isEmpty() ? "" : "  ·  " + h) + "\n" + RoutingLabels.size(sz) + big);
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
            pickAction(t.equals("geoip"), a -> { putRule(t, name, a); saveAndRender(); });
        });
        dlg.show();
    }

    // ---------------------------------------------------------------- файлы списков

    private void renderFiles() {
        beginCard("Файлы списков", "Источник: runetfreedom/russia-v2ray-rules-dat, обновляется каждые 6 часов. Около 90 МБ — лучше качать по Wi-Fi. Нужны режимам «Обход только заблокированного» и «Всё РФ напрямую».");
        boolean have = RulesFiles.present(files);
        String info = "Не загружены";
        if (have) {
            File g1 = new File(RulesFiles.dir(files), "geoip.dat"), g2 = new File(RulesFiles.dir(files), "geosite.dat");
            info = "Загружены: geoip " + (g1.length() >> 20) + " МБ, geosite " + (g2.length() >> 20) + " МБ, "
                    + new SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(new Date(Math.min(g1.lastModified(), g2.lastModified())));
            if (importBusy) info += "\nРазбираю имеющиеся файлы…";
            else if (!hasCats()) info += "\nКаталог категорий пуст: обновите списки.";
        }
        out.addView(text(dlBusy ? "Загрузка… " + dlText : info, 14, false, TEXT));
        Button b = button(have ? "Обновить списки" : "Скачать списки", v -> startDownload());
        b.setEnabled(!dlBusy);
        out.addView(b);
        endCard();
        ensureCatalog();
    }

    /**
     * Файлы уже лежат на телефоне (скачаны раньше или положены вместе с настройками), а каталога категорий нет или он старее файлов:
     * разбираем их сами, без повторной загрузки. Одна попытка на версию файлов, чтобы повреждённый файл не вызывал цикл.
     */
    private void ensureCatalog() {
        if (!RulesFiles.present(files) || dlBusy || importBusy) return;
        File g1 = new File(RulesFiles.dir(files), "geoip.dat"), g2 = new File(RulesFiles.dir(files), "geosite.dat");
        long dat = Math.max(g1.lastModified(), g2.lastModified());
        File c = new File(rstate, "rules-cats.json");
        if (cats != null && c.isFile() && c.lastModified() >= dat) return;
        if (importTried == dat) return;
        importTried = dat;
        importBusy = true;
        new Thread(() -> {
            try { Native.runVpn("rules-list --state " + rstate.getAbsolutePath(), rstate.getAbsolutePath()); } catch (Throwable ignored) { }
            ui.post(() -> {
                importBusy = false;
                if (isFinishing() || isDestroyed() || !resumed) return;
                load();
                render();
            });
        }, "knothop-rules-import").start();
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
        }, "knothop-rules-dl").start();
    }

    // ---------------------------------------------------------------- подробности

    private void renderDetails() {
        out.addView(button(showDetails ? "Скрыть подробности" : "Показать подробности", v -> { showDetails = !showDetails; render(); }));
        if (!showDetails) return;
        detailsView = text(detailsText(), 12, false, 0xFF333333);
        detailsView.setTypeface(Typeface.MONOSPACE);
        detailsView.setPadding(0, dp(8), 0, 0);
        out.addView(detailsView);
    }

    private String detailsText() {
        if (!st.active) return "VPN выключен: счётчики и дополнительные соединения появятся после подключения.";
        StringBuilder s = new StringBuilder();
        s.append("Режим: ").append(cfg.mode.equals(RoutingCfg.MODE_RULES) ? "по правилам" : "весь трафик через выход").append('\n');
        s.append("Включённых правил: ").append(cfg.enabledRules()).append(" из ").append(cfg.rules.size() + cfg.manual.size()).append('\n');
        if (st.rulesOn) {
            for (java.util.Map.Entry<String, Long> x : st.extraAge.entrySet()) {
                s.append("Доп. выход: ").append(lb.nameOf(x.getKey())).append(", ответ ").append(x.getValue()).append(" с назад\n");
            }
            if (!st.pending.isEmpty()) s.append("Поднимаю доп. выходов: ").append(st.pending.size()).append('\n');
            s.append("Пакетов по правилам: ").append(st.extraPkts).append(", ушли через выход по умолчанию вместо правила: ").append(st.fallbackPkts).append('\n');
            s.append("Не отправлено до восстановления целевой ноды: ").append(st.waitingPkts).append('\n');
        }
        return s.toString().trim();
    }
}
