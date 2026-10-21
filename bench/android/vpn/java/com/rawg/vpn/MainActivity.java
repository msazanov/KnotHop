package com.rawg.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * rawg VPN (лабораторная сборка). Первый запуск: вставить профиль-строку (спаривание). После: подключить/отключить,
 * граф выходов группы, текущий выход, выбор выхода касанием. Сервера, ключи и адрес берутся только из профиля.
 */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private SharedPreferences sp;

    private LinearLayout pairBox, mainBox, listBox, adminBox;
    private EditText profileField;
    private TextView pairMsg, header, status, logView, usersView;
    private Button button, benchBtn;
    private TextView benchView;
    private String benchLabState = "";
    private static final String BENCH_START = "bench_started_ms", BENCH_DEST = "bench_dest", BENCH_PREV_ID = "bench_prev_id", BENCH_REQ = "bench_req";
    /** Нативная часть ограничивает бенч 900 с (до 1000 МБ); с запасом. */
    private static final long BENCH_TIMEOUT_MS = 960000;
    private static final int[] BENCH_SIZES = {10, 50, 100, 300, 1000};
    /** Предел длины вставляемого или открытого по ссылке приглашения (H4/O6). */
    private static final int MAX_PASTE = 8192;
    private static final String[] RIGHTS_TEXT = {"пользоваться сетью", "пропускать транзит", "быть выходом в интернет", "зачислять новых", "отзывать права", "менять настройки сети"};
    private static final int REQ_SCAN = 4;
    private TopologyView topo;
    private long prevTs, prevUp, prevDown;
    private double rUp, rDown;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        sp = getSharedPreferences("p", MODE_PRIVATE);
        ScrollView sv = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 48, 24, 24);
        sv.addView(root);

        TextView title = new TextView(this);
        title.setText("rawg VPN");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        // --- спаривание
        pairBox = new LinearLayout(this);
        pairBox.setOrientation(LinearLayout.VERTICAL);
        TextView hint = new TextView(this);
        hint.setText("Ключ создаётся на этом телефоне при первом запуске. Вставьте приглашение (rawgi-… или строку из эмодзи) либо отсканируйте QR, если вас приглашает администратор: вы станете пользователем сети. Без приглашения телефон — администратор своей сети: он приглашает серверы и пользователей. Старый профиль rawg2-… тоже принимается.");
        pairBox.addView(hint);
        profileField = new EditText(this);
        profileField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        profileField.setMinLines(4);
        profileField.setGravity(Gravity.TOP);
        profileField.setHint("rawg2-…");
        profileField.setTextSize(11);
        pairBox.addView(profileField);
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        Button paste = new Button(this);
        paste.setText("Вставить");
        paste.setOnClickListener(v -> {
            ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData d = cb.getPrimaryClip();
            if (d != null && d.getItemCount() > 0 && d.getItemAt(0).getText() != null) profileField.setText(d.getItemAt(0).getText());
        });
        Button pair = new Button(this);
        pair.setText("Спарить");
        pair.setFilterTouchesWhenObscured(true);   // F8
        pair.setOnClickListener(v -> doPair(profileField.getText().toString()));
        row.addView(paste);
        row.addView(pair);
        pairBox.addView(row);
        Button scan = new Button(this);
        scan.setText("Сканировать QR");
        scan.setOnClickListener(v -> startActivityForResult(new Intent(this, ScanActivity.class), REQ_SCAN));
        pairBox.addView(scan);
        Button own = new Button(this);
        own.setText("Запустить без приглашения (своя сеть)");
        own.setOnClickListener(v -> doPair(""));
        pairBox.addView(own);
        pairMsg = new TextView(this);
        pairBox.addView(pairMsg);
        root.addView(pairBox);

        // --- главный экран
        mainBox = new LinearLayout(this);
        mainBox.setOrientation(LinearLayout.VERTICAL);
        header = new TextView(this);
        header.setTextSize(13);
        mainBox.addView(header);
        LinearLayout r2 = new LinearLayout(this);
        r2.setOrientation(LinearLayout.HORIZONTAL);
        button = new Button(this);
        button.setOnClickListener(v -> onButton());
        r2.addView(button);
        Button forget = new Button(this);
        forget.setText("Забыть профиль");
        forget.setOnClickListener(v -> {
            if (active() || RawgVpnService.tunHeld) startService(new Intent(this, RawgVpnService.class).setAction(RawgVpnService.A_STOP));
            sp.edit().remove("profile").apply();
            refresh();
        });
        r2.addView(forget);
        mainBox.addView(r2);
        Button routeBtn = new Button(this);
        routeBtn.setText("Маршрутизация");
        routeBtn.setAllCaps(false);
        routeBtn.setOnClickListener(v -> startActivity(new Intent(this, RoutingActivity.class)));
        mainBox.addView(routeBtn);
        Button rightsBtn = new Button(this);
        rightsBtn.setText("Мои права");
        rightsBtn.setAllCaps(false);
        rightsBtn.setOnClickListener(v -> startActivity(new Intent(this, PolicyActivity.class)));
        mainBox.addView(rightsBtn);
        // --- админ: приглашения. Видны только в своей сети (профиль «своя сеть»); пользователь по чужому приглашению их не видит.
        // Системное подтверждение личности перед выпуском сейчас ВЫКЛЮЧЕНО временно по решению владельца (Util.ADMIN_CONFIRM=false).
        adminBox = new LinearLayout(this);
        adminBox.setOrientation(LinearLayout.VERTICAL);
        TextView adminTitle = new TextView(this);
        adminTitle.setText("Администратор");
        adminTitle.setTypeface(Typeface.DEFAULT_BOLD);
        adminBox.addView(adminTitle);
        Button inviteBtn = new Button(this);
        inviteBtn.setText("Пригласить");
        inviteBtn.setFilterTouchesWhenObscured(true);   // F8
        inviteBtn.setOnClickListener(v -> startActivity(new Intent(this, InviteActivity.class)));
        adminBox.addView(inviteBtn);
        usersView = new TextView(this);
        usersView.setTextSize(12);
        adminBox.addView(usersView);
        mainBox.addView(adminBox);
        status = new TextView(this);
        status.setTextSize(13);
        status.setTypeface(Typeface.MONOSPACE);
        mainBox.addView(status);
        topo = new TopologyView(this);
        topo.setOnPick((dest, name) -> { select(dest); Util.lab("PICK " + name + " " + dest); android.widget.Toast.makeText(this, "Выход: " + name, android.widget.Toast.LENGTH_SHORT).show(); });
        mainBox.addView(topo, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 600));
        android.widget.CheckBox pingBox = new android.widget.CheckBox(this);
        pingBox.setText("Расстояние по пингу (меньше пинг — ближе)");
        pingBox.setTextSize(13);
        pingBox.setChecked(sp.getBoolean("ping_layout", false));
        topo.setPingMode(pingBox.isChecked());
        pingBox.setOnCheckedChangeListener((v, on) -> { sp.edit().putBoolean("ping_layout", on).apply(); topo.setPingMode(on); });
        mainBox.addView(pingBox);
        benchBtn = new Button(this);
        benchBtn.setText("Тест связи");
        benchBtn.setOnClickListener(v -> confirmBench());
        mainBox.addView(benchBtn);
        benchView = new TextView(this);
        benchView.setTextSize(12);
        benchView.setTypeface(Typeface.MONOSPACE);
        mainBox.addView(benchView);
        listBox = new LinearLayout(this);
        listBox.setOrientation(LinearLayout.VERTICAL);
        mainBox.addView(listBox);
        logView = new TextView(this);
        logView.setTextSize(10);
        logView.setTypeface(Typeface.MONOSPACE);
        mainBox.addView(logView);
        root.addView(mainBox);

        setContentView(sv);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != 0) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2);
        }
        handleLink(getIntent());
        handleLabIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent in) {
        super.onNewIntent(in);
        setIntent(in);
        handleLink(in);
        handleLabIntent(in);
    }

    /** Ссылка rawg://i/... (QR, открытый системной камерой): только подставляем строку в поле; зачисление начнёт сам пользователь кнопкой «Спарить». */
    private void handleLink(Intent in) {
        if (in == null || !Intent.ACTION_VIEW.equals(in.getAction()) || in.getData() == null) return;
        String u = in.getData().toString();
        in.setData(null);
        if (!u.startsWith(Profile.LINK)) return;
        if (u.length() > MAX_PASTE) {
            android.widget.Toast.makeText(this, "Ссылка слишком длинная: такого приглашения не бывает", android.widget.Toast.LENGTH_LONG).show();
            return;
        }
        if (sp.contains("profile")) {
            android.widget.Toast.makeText(this, "Телефон уже настроен. Чтобы принять другое приглашение, сначала нажмите «Забыть профиль»", android.widget.Toast.LENGTH_LONG).show();
            return;
        }
        profileField.setText(u);
        pairMsg.setText("Приглашение получено. Проверьте и нажмите «Спарить»");
    }

    @Override
    protected void onResume() {
        super.onResume();
        topo.setActive(true);
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        super.onPause();
        topo.setActive(false);
        ui.removeCallbacks(tick);
    }

    /** Управление по adb для стенда: --es profile "<строка>" / --ez auto true / --ez stop true / --es select <hash|auto> */
    private void handleLabIntent(Intent in) {
        // Команды по интентам (profile/select/stop/auto) только в лабораторной сборке: активность экспортирована, иначе любое приложение могло бы подменить профиль
        if (!Util.LAB_BUILD || in == null) return;
        String pubList = in.getStringExtra("pub");
        if (pubList != null) sp.edit().putString("lab_pub", pubList).apply();
        String p = in.getStringExtra("profile");
        if (p != null) doPair(p);
        String sel = in.getStringExtra("select");
        if (sel != null) select(sel);
        // строка приглашения уйдёт в logcat (rawgui INVITE), только в лаборатории; подтверждение личности в лабораторной сборке не требуется
        if (in.getBooleanExtra("invite", false)) {
            String r = in.getStringExtra("rights") == null ? "relay" : in.getStringExtra("rights");
            labInvite(r.matches("[a-z0-9+]{1,24}") ? r : "relay");
        }
        // H5: имитация сбоя нативной части при активном туннеле (процесс и VpnService живы, проверяется kill-switch)
        if (in.getBooleanExtra("native_fail", false)) {
            startService(new Intent(this, RawgVpnService.class).setAction(RawgVpnService.A_LAB_NATIVE_FAIL));
        }
        if (in.getBooleanExtra("stop", false)) {
            startService(new Intent(this, RawgVpnService.class).setAction(RawgVpnService.A_STOP));
        } else if (in.getBooleanExtra("auto", false) && VpnService.prepare(this) == null && !active() && sp.contains("profile")) {
            startForegroundService(new Intent(this, RawgVpnService.class).setAction(RawgVpnService.A_START)
                    .putExtra(RawgVpnService.EXTRA_ARGS, in.getStringExtra("args") == null ? "" : in.getStringExtra("args")));
        }
        if (in.getBooleanExtra("routing", false)) {
            Intent ri = new Intent(this, RoutingActivity.class);
            if (in.getStringExtra("routing_json") != null) ri.putExtra("routing", in.getStringExtra("routing_json"));
            if (in.getBooleanExtra("download", false)) ri.putExtra("download", true);
            startActivity(ri);
        }
        int benchMb = in.getIntExtra("bench_mb", 0);
        if (benchMb > 0 && benchMb <= 1000) requestBench(benchMb);
        for (String k : new String[]{"profile", "select", "auto", "stop", "pub", "invite", "rights", "bench_mb", "routing", "routing_json", "download", "native_fail"}) in.removeExtra(k);
    }

    private void doPair(String text) {
        try {
            if (text.length() > MAX_PASTE) throw new Exception("текст длиннее " + MAX_PASTE + " символов: такого приглашения не бывает");
            Profile pr = Profile.parse(text);
            // H4: чужое приглашение зачисляет только после показа ключа админа, прав, нод и срока. Лабораторная сборка управляется интентом без диалога.
            if (pr.invite && !pr.own() && !Util.LAB_BUILD) {
                confirmInvite(pr);
                return;
            }
            savePair(pr);
        } catch (Throwable e) {
            Util.lab("PAIR FAIL " + e);
            pairMsg.setText("Не удалось: " + e.getMessage());
        }
    }

    private void savePair(Profile pr) {
        Util.lab("PAIR ip=" + pr.ip + " servers=" + pr.servers);
        sp.edit().putString("profile", pr.raw).apply();
        pairMsg.setText("");
        profileField.setText("");
        refresh();
    }

    /** H4: диалог перед зачислением. Отпечатки приглашающего и корня сети, права, число входных нод и срок; пин не показываем и не логируем. */
    private void confirmInvite(Profile pr) {
        long now = System.currentTimeMillis() / 1000;
        StringBuilder m = new StringBuilder();
        m.append("Вас приглашает: ").append(fingerprint(pr.inviterHash)).append('\n');
        if (pr.delegated) m.append("в сеть: ").append(fingerprint(pr.rootHash)).append('\n');
        m.append('\n');
        m.append("Права: ").append(rightsText(pr.rights)).append('\n');
        m.append("Входные ноды: ").append(pr.nodeCount == 0 ? "любая нода этой сети" : pr.nodeCount + " (только они)").append('\n');
        m.append("Выпущено: ").append(date(pr.created)).append(", действует до ").append(date(pr.created + Profile.INVITE_TTL_S)).append('\n');
        if (pr.inviterHash.equals(ownHash())) m.append("\nПриглашение выпущено с этого телефона: его ключ уже администратор своей сети.\n");
        if (pr.rootHash.equals(ownHash())) m.append("\nЭто ваша собственная сеть: зачисляться в неё не нужно.\n");
        // срок как INVITE_TTL_S в trust.rs (проверяет нативная часть; здесь - чтобы не дать нажать «Вступить» заведомо мёртвому приглашению)
        boolean expired = now > pr.created + Profile.INVITE_TTL_S;
        if (expired) m.append("\nСрок приглашения истёк: вступить нельзя, нужно новое приглашение.\n");
        AlertDialog d = new AlertDialog.Builder(this).setTitle("Вступить в сеть?")
                .setMessage(m.toString().trim())
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Вступить", (x, w) -> savePair(pr))
                .show();
        d.getButton(DialogInterface.BUTTON_POSITIVE).setFilterTouchesWhenObscured(true);   // F8
        if (expired) d.getButton(DialogInterface.BUTTON_POSITIVE).setEnabled(false);
        d.getButton(DialogInterface.BUTTON_NEGATIVE).setFilterTouchesWhenObscured(true);
    }

    /** Первые 16 hex identity-хеша админа, группами по 4 - для сверки глазами с ключом администратора. */
    private static String fingerprint(String h) {
        return h.length() < 16 ? h : h.substring(0, 4) + " " + h.substring(4, 8) + " " + h.substring(8, 12) + " " + h.substring(12, 16);
    }

    private static String rightsText(int r) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < RIGHTS_TEXT.length; i++) if ((r & (1 << i)) != 0) s.append(s.length() == 0 ? "" : ", ").append(RIGHTS_TEXT[i]);
        return s.length() == 0 ? "нет прав" : s.toString();
    }

    private static String date(long sec) {
        return new SimpleDateFormat("dd.MM.yyyy HH:mm").format(new Date(sec * 1000));
    }

    /** identity-хеш этого телефона из whoami.json (пишет нативная часть); пусто, если ключ ещё не создан. */
    private String ownHash() {
        try { return new JSONObject(Util.read(new File(new File(getFilesDir(), "state"), "whoami.json"))).optString("hash", ""); }
        catch (Throwable ignored) { return ""; }
    }

    /**
     * Лаборатория (интент invite): приглашение без интерфейса, строка только в logcat. В обычной сборке не вызывается:
     * приглашения выпускает InviteActivity после подтверждения личности.
     */
    private void labInvite(String rights) {
        new Thread(() -> {
            File st = new File(getFilesDir(), "state");
            st.mkdirs();
            String sd = st.getAbsolutePath();
            File out = new File(st, "invite_out.txt");
            out.delete();
            int rc = Native.runVpn("whoami --state " + sd, sd);
            if (rc == 0) rc = Native.runVpn("invite --state " + sd + " --rights " + rights + " --label lab --out " + out.getAbsolutePath(), sd);
            final String text = rc == 0 ? Util.read(out).trim() : "ошибка: " + Util.read(new File(st, "error.txt"));
            out.delete();
            Util.lab("INVITE " + text);
        }, "rawg-invite").start();
    }

    private boolean active() {
        String p = RawgVpnService.phase;
        return !"idle".equals(p) && !"error".equals(p);
    }

    private void onButton() {
        if (active() || RawgVpnService.tunHeld) {
            startService(new Intent(this, RawgVpnService.class).setAction(RawgVpnService.A_STOP));
            return;
        }
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, REQ_VPN);
        else startVpn();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_VPN && res == RESULT_OK) startVpn();
        if (req == REQ_SCAN && res == RESULT_OK && data != null) {
            String t = data.getStringExtra(ScanActivity.EXTRA_TEXT);
            if (t != null) {
                profileField.setText(t);
                pairMsg.setText("QR считан. Проверьте и нажмите «Спарить»");
            }
        }
    }

    private void startVpn() {
        startForegroundService(new Intent(this, RawgVpnService.class).setAction(RawgVpnService.A_START));
    }

    /** Выбор выхода: файл select в каталоге состояния читает нативная часть. Без выбора (или пока выбранный выход недоступен) нативная часть сама берёт лучший. */
    private void select(String dest) {
        try {
            File st = new File(getFilesDir(), "state");
            st.mkdirs();
            java.nio.file.Files.write(new File(st, "select").toPath(), dest.getBytes("UTF-8"));
        } catch (Exception ignored) { }
    }

    private final Runnable tick = new Runnable() {
        public void run() {
            refresh();
            ui.postDelayed(this, 1000);
        }
    };

    private static String mb(long b) {
        return String.format("%.1f МБ", b / 1e6);
    }

    private void refresh() {
        String saved = sp.getString("profile", "");
        boolean paired = sp.contains("profile");   // пустая строка - тоже настроено: «своя сеть»
        pairBox.setVisibility(paired ? View.GONE : View.VISIBLE);
        mainBox.setVisibility(paired ? View.VISIBLE : View.GONE);
        if (!paired) return;
        try {
            Profile pr = Profile.parse(saved);
            String model = pr.v3 ? " [0012, таблица v" + pr.tableVer + "]" : "";
            adminBox.setVisibility(pr.own() ? View.VISIBLE : View.GONE);   // приглашать может только администратор своей сети
            if (pr.own()) header.setText("Вы администратор своей сети. Кнопка «Пригласить»: выбор нод и прав; приглашение показывается как QR и строка и нигде не сохраняется. Нажмите «Подключить» и держите приложение включённым, пока приглашённый не зачислится: вы подтверждаете его, а ноды сети узнают о нём автоматически");
            else if (pr.invite) header.setText(enrolled()
                    ? grantedHeader()
                    : "Приглашение принято, зачисление ещё не завершено. Нажмите «Подключить»: телефон найдёт ноды сети и попросит администратора подтвердить вас (его телефон в этот момент должен быть подключён)");
            else header.setText("группа «" + pr.group + "», серверов в профиле: " + pr.servers + ", ваш адрес " + pr.ip + model);
        } catch (Throwable e) {
            header.setText("профиль повреждён: " + e.getMessage());
        }
        button.setText(active() || RawgVpnService.tunHeld ? "Отключить" : "Подключить");
        StringBuilder s = new StringBuilder("состояние: ").append(RawgVpnService.phase).append('\n');
        if (!RawgVpnService.lastError.isEmpty()) s.append("ОШИБКА: ").append(RawgVpnService.lastError).append('\n');
        File state = new File(getFilesDir(), "state");
        JSONObject j = null;
        try {
            String js = Util.read(new File(state, "status.json"));
            if (!js.isEmpty() && active()) j = new JSONObject(js);
        } catch (Throwable ignored) { }
        if (j != null) {
            try {
                JSONObject cur = j.optJSONObject("current");
                s.append("выход: ").append(cur == null ? "— (ищу)" : TopologyView.shortName(cur.optString("n")) + " (" + cur.optString("d").substring(0, 8) + ")").append('\n');
                if (cur != null && !cur.isNull("via")) {
                    String vd = cur.optString("via"); String vn = vd;
                    JSONArray exs = j.optJSONArray("exits");
                    for (int q = 0; exs != null && q < exs.length(); q++) if (vd.equals(exs.optJSONObject(q).optString("d"))) vn = TopologyView.shortName(exs.optJSONObject(q).optString("n"));
                    s.append("маршрут: телефон -> ").append(vn).append(" -> ").append(TopologyView.shortName(cur.optString("n"))).append('\n');
                }
                if (cur != null) s.append("носитель: ").append(TopologyView.carrierName(cur.optString("carrier"))).append(" (открытый сокет, не путь RNS)\n");
                s.append(TopologyView.prettify(j.optString("status"))).append('\n');
                updateBenchUi(state, j, cur);
                JSONObject t = j.getJSONObject("tun");
                long up = t.getLong("from_tun_bytes"), down = t.getLong("to_tun_bytes"), sts = j.getLong("ts_ms");
                if (prevTs != 0 && sts > prevTs) {
                    double dt = (sts - prevTs) / 1000.0;
                    rUp = (up - prevUp) * 8 / dt / 1e6;
                    rDown = (down - prevDown) * 8 / dt / 1e6;
                }
                if (sts != prevTs) { prevUp = up; prevDown = down; prevTs = sts; }
                s.append(String.format("вверх %s  %.1f Мбит/с\nвниз  %s  %.1f Мбит/с\n", mb(up), rUp, mb(down), rDown));
                JSONArray fo = j.optJSONArray("failovers");
                s.append("смен выхода: ").append(fo == null ? 0 : fo.length());
                JSONArray us = j.optJSONArray("users");
                StringBuilder ut = new StringBuilder();
                for (int q = 0; us != null && q < us.length(); q++) ut.append(q == 0 ? "" : ", ").append(us.optJSONObject(q).optString("h"));
                usersView.setText(ut.length() == 0 ? "" : "Зачислены с этого запуска: " + ut);
                topo.update(j);
                JSONArray lt = j.optJSONArray("log_tail");
                if (lt != null) for (int q = lt.length() - 1; q >= 0; q--) { String ln = lt.optString(q); if (logSeen.add(ln)) Util.lab("NLOG " + ln); }
                buildList(j);
            } catch (Throwable e) {
                s.append("статус: ").append(e);
            }
        } else {
            prevTs = 0;
            rUp = rDown = 0;
            try { topo.update(new JSONObject("{\"state\":\"idle\",\"ip\":\"\"}")); } catch (Exception ignored) { }
            listBox.removeAllViews();
            listSig = "";
            updateBenchUi(state, null, null);
        }
        status.setText(s);
        Util.lab("STATUS " + s.toString().replace("\n", " | "));
        String log = Util.read(new File(state, "log.txt"));
        String[] lines = log.split("\n");
        StringBuilder l = new StringBuilder();
        for (int i = Math.max(0, lines.length - 8); i < lines.length; i++) { String ln = TopologyView.prettify(lines[i]); l.append(ln.length() > 110 ? ln.substring(0, 110) : ln).append('\n'); }
        logView.setText(l);
        if (lines.length > 0) Util.lab("LOG " + lines[lines.length - 1]);
    }

    private void confirmBench() {
        JSONObject current = currentStatus();
        JSONObject cur = current == null ? null : current.optJSONObject("current");
        String dest = cur == null ? "" : cur.optString("d", "");
        if (!active() || !dest.matches("[0-9a-fA-F]{32}")) {
            android.widget.Toast.makeText(this, "Сначала подключите VPN и выберите текущий выход", android.widget.Toast.LENGTH_LONG).show();
            return;
        }
        String name = cur.optString("n", dest.substring(0, 8));
        String[] labels = new String[BENCH_SIZES.length];
        for (int i = 0; i < BENCH_SIZES.length; i++) labels[i] = BENCH_SIZES[i] + " МБ";
        // объём выбирает пользователь: выход отдаёт данные телефону по Link RNS (без интернета), мерим приём
        new AlertDialog.Builder(this).setTitle("Тест связи через «" + name + "» (" + dest.substring(0, 8) + "…)")
                .setItems(labels, (d, w) -> requestBench(BENCH_SIZES[w]))
                .setNegativeButton("Отмена", null)
                .show();
    }

    private JSONObject currentStatus() {
        try { return new JSONObject(Util.read(new File(new File(getFilesDir(), "state"), "status.json"))); }
        catch (Throwable ignored) { return null; }
    }

    /** Shared by the explicit UI confirmation and the LAB_BUILD-only automation intent. */
    private boolean requestBench(int mb) {
        if (!active()) { Util.lab("BENCH rejected vpn-down"); return false; }
        JSONObject status = currentStatus();
        JSONObject cur = status == null ? null : status.optJSONObject("current");
        String dest = cur == null ? "" : cur.optString("d", "");
        if (!dest.matches("[0-9a-fA-F]{32}")) { Util.lab("BENCH rejected no-current-exit"); return false; }
        long now = System.currentTimeMillis();
        long old = sp.getLong(BENCH_START, 0);
        File state = new File(getFilesDir(), "state");
        if (old > 0 && now - old < BENCH_TIMEOUT_MS && benchResult(state, old) == null) {
            Util.lab("BENCH rejected already-running");
            return false;
        }
        try {
            if (!state.exists() && !state.mkdirs()) throw new Exception("state directory unavailable");
            // id последнего результата до запроса: новый результат обязан иметь другой id (id назначает нативная часть)
            long prevId = benchResId(new File(state, "bench-res.json"));
            String req = "r" + Long.toString(now, 36);
            File target = new File(state, "bench-req");
            File tmp = new File(state, "bench-req.tmp");
            try (FileOutputStream out = new FileOutputStream(tmp)) {
                // req - метка запроса: нативная часть возвращает её в bench-res.json, по ней сверяем «наш» результат
                out.write((dest + " " + mb + " req=" + req).getBytes(StandardCharsets.US_ASCII));
                out.getFD().sync();
            }
            if (!tmp.renameTo(target)) { tmp.delete(); throw new Exception("atomic rename failed"); }
            sp.edit().putLong(BENCH_START, now).putString(BENCH_DEST, dest).putLong(BENCH_PREV_ID, prevId).putString(BENCH_REQ, req).apply();
            benchLabState = "";
            Util.lab("BENCH queued to=" + dest + " mb=" + mb);
            refresh();
            return true;
        } catch (Throwable e) {
            Util.lab("BENCH write-failed " + e.getClass().getSimpleName());
            android.widget.Toast.makeText(this, "Не удалось записать запрос теста", android.widget.Toast.LENGTH_LONG).show();
            return false;
        }
    }

    /** id результата в bench-res.json; -1 - файла нет или id не разобран. */
    private static long benchResId(File f) {
        try { return new JSONObject(Util.read(f)).optLong("id", -1); }
        catch (Throwable e) { return -1; }
    }

    /**
     * Результат именно нашего запроса: файл появился после старта и несёт нашу метку req (её возвращает нативная часть). null - результата нет.
     */
    private JSONObject benchResult(File state, long started) {
        File f = new File(state, "bench-res.json");
        if (started <= 0 || !f.isFile() || f.lastModified() <= started) return null;
        try {
            JSONObject b = new JSONObject(Util.read(f));
            String req = sp.getString(BENCH_REQ, "");
            if (req.isEmpty() || !req.equals(b.optString("req", ""))) return null;
            return b;
        } catch (Throwable e) {
            return null;
        }
    }

    private void updateBenchUi(File state, JSONObject status, JSONObject cur) {
        if (benchBtn == null) return;
        long started = sp.getLong(BENCH_START, 0);
        String dest = cur == null ? "" : cur.optString("d", "");
        boolean canRun = active() && dest.matches("[0-9a-fA-F]{32}");
        JSONObject res = benchResult(state, started);
        boolean timedOut = started > 0 && System.currentTimeMillis() - started >= BENCH_TIMEOUT_MS;
        boolean running = started > 0 && !timedOut && res == null;
        benchBtn.setEnabled(canRun && !running);
        if (running && !dest.equals(sp.getString(BENCH_DEST, ""))) {
            benchView.setText("Тест выполняется через предыдущий текущий выход");
        } else if (running) {
            benchView.setText("Тест выполняется… (таймаут до 180 с)");
        } else if (res == null && timedOut) {
            benchView.setText("Тест: таймаут");
            reportBench("таймаут");
        } else if (res != null) {
            String resultDest = res.optString("to", "");
            String text = "Тест: " + res.optString("verdict", "готов") + " · " + res.optString("mbps", "—") + " МБ/с · "
                    + res.optString("pps", "—") + " пак/с · потери " + res.optString("pkts_lost", "—")
                    + (resultDest.isEmpty() ? "" : " · " + resultDest.substring(0, Math.min(24, resultDest.length())));   // to - имя ноды, не dest
            benchView.setText(text);
            if (!text.equals(benchLabState)) Util.lab("BENCH_RESULT " + res.toString());
            reportBench(text);
        } else {
            benchView.setText(canRun ? "Текущий выход готов к тесту" : "Тест доступен при VPN и выбранном выходе");
        }
    }

    private void reportBench(String text) {
        if (!text.equals(benchLabState)) { benchLabState = text; Util.lab("BENCH " + text); }
    }

    /** Пользователь уже зачислен: в trust.json есть чужой якорь (админ приглашения). Файл пишет нативная часть при зачислении. */
    /** Заголовок по действующим правам из status.json (выдал админ чужой сети), а не по виду приглашения. */
    private String grantedHeader() {
        int g = 0;
        try {
            File st = new File(getFilesDir(), "state");
            String own = "";
            try { own = new JSONObject(Util.read(new File(st, "whoami.json"))).optString("hash", ""); } catch (Throwable ignored) { }
            JSONArray pol = new JSONObject(Util.read(new File(st, "status.json"))).optJSONArray("policy");
            for (int i = 0; pol != null && i < pol.length(); i++) {
                JSONObject p = pol.getJSONObject(i);
                if (!p.optString("root", "").equals(own)) g |= p.optInt("grant");
            }
        } catch (Throwable ignored) { }
        if (g == 0) return "Вы пользователь сети. Права появятся после подключения";
        String[] names = {"пользоваться", "транзит", "выход", "приглашать", "отзывать", "настройки"};
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < names.length; i++) if ((g & (1 << i)) != 0) b.append(b.length() == 0 ? "" : ", ").append(names[i]);
        return "Вы участник сети: права (" + b + ") выдал администратор. " + ((g & 8) != 0 ? "Право приглашать выдано, но кнопка «Пригласить» пока есть только у администратора сети" : "Приглашать других вам нельзя");
    }

    private boolean enrolled() {
        try {
            JSONArray a = new JSONObject(Util.read(new File(new File(getFilesDir(), "state"), "trust.json"))).optJSONArray("anchors");
            return a != null && a.length() > 0;
        } catch (Throwable e) {
            return false;
        }
    }

    private final java.util.Set<String> logSeen = new java.util.HashSet<>();
    private String listSig = "";
    private final java.util.Map<String, TextView> rows = new java.util.HashMap<>();

    /** Список выходов: строки создаются один раз на набор узлов и только обновляются (иначе нажатие терялось: вид заменялся между DOWN и UP). */
    private void buildList(JSONObject j) {
        JSONArray ex = j.optJSONArray("exits");
        if (ex == null) return;
        RoutingCfg.cacheNodes(getFilesDir(), ex);
        StringBuilder sig = new StringBuilder();
        for (int i = 0; i < ex.length(); i++) sig.append(ex.optJSONObject(i).optString("d")).append(',');
        if (!sig.toString().equals(listSig)) {
            listSig = sig.toString();
            listBox.removeAllViews();
            rows.clear();
            for (int i = 0; i < ex.length(); i++) {
                final JSONObject e = ex.optJSONObject(i);
                final String dest = e.optString("d");
                final String name = e.optString("n");
                TextView tv = new TextView(this);
                tv.setTextSize(14);
                tv.setPadding(12, 22, 12, 22);
                tv.setClickable(true);
                tv.setOnClickListener(v -> {
                    select(dest);
                    Util.lab("PICK(list) " + name + " " + dest);
                    android.widget.Toast.makeText(this, "Выход: " + name, android.widget.Toast.LENGTH_SHORT).show();
                });
                rows.put(dest, tv);
                listBox.addView(tv);
            }
        }
        for (int i = 0; i < ex.length(); i++) {
            JSONObject e = ex.optJSONObject(i);
            String st = e.optString("s");
            TextView tv = rows.get(e.optString("d"));
            if (tv == null) continue;
            // A failed local Link is not a dead node; reports cover only observed neighbours.
            boolean v = e.optBoolean("v"), fail = "fail".equals(e.optString("lk"));
            int reporters = e.optInt("ra", 0);
            String vis = e.isNull("vis") ? "" : e.optString("vis");   // R8: direct | via | none; пусто - старая нативная часть
            String car = "носитель " + TopologyView.carrierName(e.optString("c"));
            String why = TopologyView.whyText(e.isNull("why") ? "" : e.optString("why"));
            String how = fail ? (v ? car + " · " : "") + "мой Link недоступен" + (why.isEmpty() ? "" : ": " + why)
                    : "none".equals(vis) ? (reporters > 0 ? "видят другие узлы" : v ? "носитель есть, пути нет" : "нет свежих данных") : "via".equals(vis) ? "через транзит"
                    : v ? car + (e.isNull("pr") ? "" : " " + Math.round(e.optDouble("pr")) + " мс") : (reporters > 0 ? "видят другие узлы" : "нет свежих данных");
            // R9: качество Link - удачные/неудачные попытки, смен пути, секунд с последнего удачного контакта
            JSONObject q = e.optJSONObject("q");
            String qs = q == null ? "" : "Link " + q.optInt("ok") + "/" + q.optInt("fail") + ", смен пути " + q.optInt("pc")
                    + (q.isNull("age") ? "" : ", был " + q.optLong("age") + " с назад");
            String label = ("current".equals(st) ? "● " : "○ ") + TopologyView.shortName(e.optString("n")) + (e.isNull("pl") ? "" : " " + TopologyView.kindIcon(e.optString("pl"))) + "   " + how
                    + (e.isNull("h") || fail ? "" : ", путь RNS " + e.optInt("h") + " хоп")
                    + (e.isNull("r") || e.optDouble("r", 0) <= 0 || "current".equals(st) ? "" : ", +" + Math.round(e.optDouble("r")) + " мс")
                    + ("current".equals(st) ? "   ТЕКУЩИЙ" : "")
                    + (qs.isEmpty() ? "" : "\n" + qs);
            if (!label.contentEquals(tv.getText())) Util.lab("ROW " + label.replace("\n", " | "));
            tv.setText(label);
            tv.setTypeface("current".equals(st) ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
            tv.setTextColor("current".equals(st) ? 0xFF2E9E4F : 0xFF222222);
        }
        listBox.setVisibility(View.VISIBLE);
    }
}
