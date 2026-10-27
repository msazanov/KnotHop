package com.knothop.vpn;

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
import android.view.WindowManager;
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
 * KnotHop VPN (лабораторная сборка). Первый запуск: вставить профиль-строку (спаривание). После: подключить/отключить,
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
    /** Предел длины вставляемого или открытого по ссылке приглашения (H4/O6). */
    private static final int MAX_PASTE = 4096;
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
        title.setText("KnotHop");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        // --- спаривание
        pairBox = new LinearLayout(this);
        pairBox.setOrientation(LinearLayout.VERTICAL);
        TextView hint = new TextView(this);
        hint.setText("Ключ создаётся на этом телефоне при первом запуске. Вставьте приглашение kh-… или отсканируйте QR, если вас приглашает администратор (оно действует 48 часов и одноразовое). Без приглашения телефон — администратор своей сети.");
        pairBox.addView(hint);
        profileField = new EditText(this);
        profileField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        profileField.setMinLines(4);
        profileField.setGravity(Gravity.TOP);
        profileField.setHint("kh-…");
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
            if (active() || KnotHopVpnService.tunHeld) startService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_STOP));
            forgetProfile();
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
        Button nodesBtn = new Button(this);
        nodesBtn.setText("Обновить список нод");
        nodesBtn.setAllCaps(false);
        nodesBtn.setOnClickListener(v -> refreshNodes());
        mainBox.addView(nodesBtn);
        // --- админ: приглашения. Видны только в своей сети (профиль «своя сеть»); пользователь по чужому приглашению их не видит.
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
        topo.setOnLongPick((dest, name) -> openNodeAdmin(dest, name, ""));
        topo.setOnPhonePick(() -> startActivity(new Intent(this, MyNodeActivity.class)));
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

    /** Ссылка KnotHop://i/... (QR, открытый системной камерой): только подставляем строку в поле; зачисление начнёт сам пользователь кнопкой «Спарить». */
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
        // строка приглашения уйдёт в logcat (knothopui INVITE), только в лаборатории; нужен --es nodes <хеш[,хеш]>; согласие новичка в лаборатории принимается само
        if (in.getBooleanExtra("invite", false)) {
            String r = in.getStringExtra("rights") == null ? "use+transit+exit" : in.getStringExtra("rights");
            String n = in.getStringExtra("nodes") == null ? "" : in.getStringExtra("nodes");
            if (n.matches("[0-9a-f]{32}(,[0-9a-f]{32}){0,7}")) labInvite(r.matches("[a-z0-9+]{1,24}") ? r : "use+transit+exit", n);
        }
        // H5: имитация сбоя нативной части при активном туннеле (процесс и VpnService живы, проверяется kill-switch)
        if (in.getBooleanExtra("native_fail", false)) {
            startService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_LAB_NATIVE_FAIL));
        }
        if (in.getBooleanExtra("stop", false)) {
            startService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_STOP));
        } else if (in.getBooleanExtra("auto", false) && VpnService.prepare(this) == null && !active() && sp.contains("profile")) {
            startForegroundService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_START)
                    .putExtra(KnotHopVpnService.EXTRA_ARGS, in.getStringExtra("args") == null ? "" : in.getStringExtra("args")));
        }
        if (in.getBooleanExtra("routing", false)) {
            Intent ri = new Intent(this, RoutingActivity.class);
            if (in.getStringExtra("routing_json") != null) ri.putExtra("routing", in.getStringExtra("routing_json"));
            if (in.getBooleanExtra("download", false)) ri.putExtra("download", true);
            startActivity(ri);
        }
        int benchMb = in.getIntExtra("bench_mb", 0);
        if (benchMb > 0 && benchMb <= 25) requestBench(benchMb);
        for (String k : new String[]{"profile", "select", "auto", "stop", "pub", "invite", "rights", "nodes", "bench_mb", "routing", "routing_json", "download", "native_fail"}) in.removeExtra(k);
    }

    private void doPair(String text) {
        try {
            if (text.length() > MAX_PASTE) throw new Exception("текст длиннее " + MAX_PASTE + " символов: такого приглашения не бывает");
            Profile pr = Profile.parse(text);
            // Права, срок и корень сети приглашение не несёт: их присылает нода, и пользователь соглашается в диалоге (pollOffer) до погашения.
            savePair(pr);
        } catch (Throwable e) {
            Util.lab("PAIR FAIL " + e);
            pairMsg.setText("Не удалось: " + e.getMessage());
        }
    }

    private void savePair(Profile pr) {
        new File(new File(getFilesDir(), "state"), "enrollment.json").delete();
        new File(new File(getFilesDir(), "state"), "enroll-consent.json").delete();
        offerShown = "";
        sp.edit().putString("profile", pr.raw).apply();
        pairMsg.setText("");
        profileField.setText("");
        refresh();
    }

    /**
     * «Забыть профиль» (R-2, R-3): профиль, приглашение, зачисление и чужие корни доверия. Идентичность телефона и записи его
     * собственной сети остаются. Чужие якоря стирает нативная часть (`forget-network`) после остановки службы.
     */
    private void forgetProfile() {
        File st = new File(getFilesDir(), "state");
        sp.edit().remove("profile").apply();
        for (int i = 0; i < 30 && (active() || KnotHopVpnService.tunHeld); i++) {   // служба останавливается асинхронно, до 3 с
            try { Thread.sleep(100); } catch (InterruptedException e) { break; }
        }
        for (String n : new String[]{"profile.txt", "enrollment.json", "enroll-consent.json", "enroll-consented.json", "status.json"}) new File(st, n).delete();
        offerShown = "";
        if (new File(st, "identity.key").exists()) {
            String sd = st.getAbsolutePath();
            if (Native.runVpn("forget-network --state " + sd, sd) != 0) {
                android.widget.Toast.makeText(this, "Не удалось забыть чужие сети: " + Util.read(new File(st, "error.txt")), android.widget.Toast.LENGTH_LONG).show();
            }
        }
    }

    /**
     * R-3: после завершения зачисления приглашение (и pin в нём) бессрочно не хранится. Принятое или отклонённое приглашение
     * заменяется записью без pin, а state/profile.txt стирается. Состояние зачисления пишет нативная часть (enrollment.json).
     */
    private void retirePin() {
        String saved = sp.getString("profile", "");
        if (!saved.startsWith("kh-")) return;
        File st = new File(getFilesDir(), "state");
        String state;
        try { state = new JSONObject(Util.read(new File(st, "enrollment.json"))).optString("state", ""); } catch (Throwable e) { return; }
        if ("enrolled".equals(state)) {
            sp.edit().putString("profile", Profile.ENROLLED).apply();
        } else if ("declined".equals(state) || "refused".equals(state)) {
            sp.edit().remove("profile").apply();   // отказ терминален (свой или всех нод): приглашение стирается, нужно новое
            new File(st, "enrollment.json").delete();
            offerShown = "";
        } else {
            return;
        }
        new File(st, "profile.txt").delete();
    }

    private String offerShown = "";
    private AlertDialog offerDialog;

    /**
     * Согласие новичка (ADR 0019): нативная часть получила подписанное предложение ноды и ждёт ответа в state/enroll-consent.json.
     * Показываем корень сети, приглашающего, права и срок из подписанного предложения; pin в файл не попадает и здесь не виден.
     */
    private void pollOffer() {
        if (offerDialog != null && offerDialog.isShowing()) return;
        File st = new File(getFilesDir(), "state");
        File f = new File(st, "enrollment.json");
        long now = System.currentTimeMillis() / 1000;
        if (!f.exists() || f.lastModified() / 1000 < now - 290 || !active()) return;
        JSONObject o;
        try { o = new JSONObject(Util.read(f)); } catch (Throwable e) { return; }
        String req = o.optString("request", "");
        if (!"offer".equals(o.optString("state")) || !req.matches("[0-9a-f]{8,128}") || req.equals(offerShown)) return;
        offerShown = req;
        String root = o.optString("root", ""), issuer = o.optString("issuer", "");
        int rights = o.optInt("rights");
        long exp = o.optLong("expires");
        JSONArray nd = o.optJSONArray("nodes");
        JSONArray others = o.optJSONArray("others");
        if (Util.LAB_BUILD) { writeConsent(req, true); return; }
        StringBuilder m = new StringBuilder();
        m.append("Вас приглашает: ").append(fingerprint(issuer)).append('\n');
        m.append("в сеть: ").append(fingerprint(root)).append("\n\n");
        m.append("Права: ").append(rightsText(rights)).append('\n');
        m.append("Ноды, выдающие права: ").append(nd == null ? 0 : nd.length()).append('\n');
        for (int i = 0; nd != null && i < Math.min(nd.length(), 8); i++) m.append("  ").append(fingerprint(nd.optString(i, ""))).append('\n');
        m.append("Приглашение действует до ").append(date(exp)).append('\n');
        if (others != null && others.length() > 0) {
            m.append("\nВнимание: это устройство уже доверяет ").append(others.length()).append(" другим сетям (");
            for (int i = 0; i < Math.min(others.length(), 4); i++) m.append(i == 0 ? "" : ", ").append(fingerprint(others.optString(i, "")));
            m.append("). Новая сеть добавится к ним; чтобы остаться только в новой, сначала нажмите «Забыть профиль».\n");
        }
        if (root.equals(ownHash())) m.append("\nЭто ваша собственная сеть: зачисляться в неё не нужно.\n");
        boolean expired = now > exp;
        if (expired) m.append("\nСрок приглашения истёк: вступить нельзя, нужно новое приглашение.\n");
        offerDialog = new AlertDialog.Builder(this).setTitle("Вступить в сеть?")
                .setMessage(m.toString().trim())
                .setCancelable(false)
                .setNegativeButton("Отмена", (x, w) -> writeConsent(req, false))
                .setPositiveButton("Вступить", (x, w) -> writeConsent(req, true))
                .show();
        offerDialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);   // R-10: корень сети и права не попадают в скриншоты
        offerDialog.getButton(DialogInterface.BUTTON_POSITIVE).setFilterTouchesWhenObscured(true);   // F8
        if (expired) offerDialog.getButton(DialogInterface.BUTTON_POSITIVE).setEnabled(false);
        offerDialog.getButton(DialogInterface.BUTTON_NEGATIVE).setFilterTouchesWhenObscured(true);
    }

    /** Ответ нативной части: атомарно (временный файл и переименование), только для показанного предложения. */
    private void writeConsent(String request, boolean accept) {
        try {
            File st = new File(getFilesDir(), "state");
            File tmp = new File(st, "enroll-consent.json.tmp");
            java.nio.file.Files.write(tmp.toPath(), new JSONObject().put("request", request).put("accept", accept).toString().getBytes(StandardCharsets.UTF_8));
            java.nio.file.Files.move(tmp.toPath(), new File(st, "enroll-consent.json").toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Throwable e) {
            Util.lab("consent write failed: " + e);
        }
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
     * приглашения выпускает InviteActivity.
     */
    private void labInvite(String rights, String nodes) {
        new Thread(() -> {
            File st = new File(getFilesDir(), "state");
            st.mkdirs();
            String sd = st.getAbsolutePath();
            File out = new File(st, "invite_out.txt");
            out.delete();
            int rc = Native.runVpn("whoami --state " + sd, sd);
            if (rc == 0) rc = Native.runVpn("invite --state " + sd + " --rights " + rights + " --nodes " + nodes + " --out " + out.getAbsolutePath(), sd);
            final String text = rc == 0 ? Util.read(out).trim() : "ошибка: " + Util.read(new File(st, "error.txt"));
            out.delete();
            Util.lab("INVITE " + text);
        }, "knothop-invite").start();
    }

    private boolean active() {
        String p = KnotHopVpnService.phase;
        return !"idle".equals(p) && !"error".equals(p);
    }

    private void onButton() {
        if (active() || KnotHopVpnService.tunHeld) {
            startService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_STOP));
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
        startForegroundService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_START));
    }

    /** Выбор выхода: файл select в каталоге состояния читает нативная часть. Без выбора (или пока выбранный выход недоступен) нативная часть сама берёт лучший. */
    private void select(String dest) {
        try {
            File st = new File(getFilesDir(), "state");
            st.mkdirs();
            java.nio.file.Files.write(new File(st, "select").toPath(), dest.getBytes("UTF-8"));
        } catch (Exception ignored) { }
    }

    /** Дожим расписок зачисления: файл refresh-nodes читает нативная часть (раз в 5 с); сама она делает это и раз в 2 мин. Нужен подключённый VPN. */
    private void refreshNodes() {
        if (!(active() || KnotHopVpnService.tunHeld)) {
            android.widget.Toast.makeText(this, "Сначала подключитесь", android.widget.Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            File st = new File(getFilesDir(), "state");
            st.mkdirs();
            new File(st, "refresh-nodes").createNewFile();
            android.widget.Toast.makeText(this, "Запрашиваю остальные ноды у сети", android.widget.Toast.LENGTH_SHORT).show();
        } catch (Exception ignored) { }
    }

    private final Runnable tick = new Runnable() {
        public void run() {
            refresh();
            pollOffer();
            ui.postDelayed(this, 1000);
        }
    };

    private static String mb(long b) {
        return String.format("%.1f МБ", b / 1e6);
    }

    private void refresh() {
        retirePin();
        String saved = sp.getString("profile", "");
        boolean paired = sp.contains("profile");   // пустая строка - тоже настроено: «своя сеть»
        // R-10: пока видно поле ввода приглашения, окно закрыто от скриншотов, записи экрана и превью в списке задач
        if (paired) getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        else getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        pairBox.setVisibility(paired ? View.GONE : View.VISIBLE);
        mainBox.setVisibility(paired ? View.VISIBLE : View.GONE);
        if (!paired) return;
        try {
            Profile pr = Profile.parse(saved);
            adminBox.setVisibility(pr.own() ? View.VISIBLE : View.GONE);   // приглашать может только администратор своей сети
            if (pr.own()) header.setText("Вы администратор своей сети. Кнопка «Пригласить»: выбор нод и прав; приглашение показывается как QR и строка и нигде не сохраняется. Приглашение действует 48 часов; выбранные ноды сами выдадут права, держать приложение включённым после выпуска не нужно (но при выпуске телефон должен быть подключён)");
            else header.setText(enrolled()
                    ? grantedHeader()
                    : "Приглашение принято, зачисление ещё не завершено. Нажмите «Подключить»: телефон свяжется с нодами приглашения и покажет, какие права вам предлагают; согласитесь в диалоге");
        } catch (Throwable e) {
            header.setText("профиль повреждён: " + e.getMessage());
        }
        button.setText(active() || KnotHopVpnService.tunHeld ? "Отключить" : "Подключить");
        StringBuilder s = new StringBuilder("состояние: ").append(KnotHopVpnService.phase).append('\n');
        if (!KnotHopVpnService.lastError.isEmpty()) s.append("ОШИБКА: ").append(KnotHopVpnService.lastError).append('\n');
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
        if (KnotHopVpnService.speedPath() == null) {
            new AlertDialog.Builder(this).setMessage("Тест требует подключённый VPN без исключённых подсетей. Сокеты теста не могут идти мимо туннеля.").setPositiveButton("OK", null).show();
            return;
        }
        LinearLayout fields = new LinearLayout(this);
        fields.setOrientation(LinearLayout.VERTICAL);
        TextView warning = new TextView(this);
        warning.setText("Обычный HTTP(S) через VPN, до 25 МБ / 15 с на направление (до 50 МБ суммарно). HTTP не шифруется. Download URL: {bytes} заменяется объёмом.");
        fields.addView(warning);
        EditText down = new EditText(this), up = new EditText(this);
        down.setSingleLine(true); up.setSingleLine(true);
        down.setText(sp.getString("speed_down", SpeedTransfer.DOWN));
        up.setText(sp.getString("speed_up", SpeedTransfer.UP));
        fields.addView(down); fields.addView(up);
        new AlertDialog.Builder(this).setTitle("Тест связи: интернет через VPN").setView(fields)
            .setPositiveButton("Начать", (d, w) -> {
                try {
                    String dl = down.getText().toString().trim(), ul = up.getText().toString().trim();
                    SpeedTransfer.endpoint(dl, SpeedTransfer.MAX_BYTES); SpeedTransfer.endpoint(ul, SpeedTransfer.MAX_BYTES);
                    sp.edit().putString("speed_down", dl).putString("speed_up", ul).apply();
                    requestBench(25);
                } catch (Exception e) { benchView.setText(e.getMessage()); }
            }).setNegativeButton("Отмена", null).show();
    }

    private JSONObject currentStatus() {
        try { return new JSONObject(Util.read(new File(new File(getFilesDir(), "state"), "status.json"))); }
        catch (Throwable ignored) { return null; }
    }

    private boolean requestBench(int mb) {
        if (mb < 1 || mb > 25) return false;
        boolean started = SpeedTest.start(KnotHopVpnService.speedPath(),
                sp.getString("speed_down", SpeedTransfer.DOWN), sp.getString("speed_up", SpeedTransfer.UP), mb * 1_000_000L);
        if (!started) benchView.setText("Нет подключённого VPN или тест уже запущен");
        refresh();
        return started;
    }

    private void updateBenchUi(File state, JSONObject status, JSONObject cur) {
        if (benchBtn == null) return;
        benchBtn.setEnabled("up".equals(KnotHopVpnService.phase) && !SpeedTest.running());
        benchView.setText(SpeedTest.text);
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
                LinearLayout row = new LinearLayout(this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                TextView tv = new TextView(this);
                tv.setTextSize(14);
                tv.setPadding(12, 22, 12, 22);
                tv.setClickable(true);
                tv.setOnClickListener(v -> {
                    select(dest);
                    Util.lab("PICK(list) " + name + " " + dest);
                    android.widget.Toast.makeText(this, "Выход: " + name, android.widget.Toast.LENGTH_SHORT).show();
                });
                Button more = new Button(this);
                more.setText("⋯");
                more.setAllCaps(false);
                more.setContentDescription("Управление нодой " + name);
                more.setMinWidth((int) (48 * getResources().getDisplayMetrics().density));
                more.setOnClickListener(v -> openNodeAdmin(dest, name, e.optString("id", "")));
                rows.put(dest, tv);
                row.addView(tv, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
                row.addView(more, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.MATCH_PARENT));
                listBox.addView(row);
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

    private void openNodeAdmin(String dest, String name, String fingerprint) {
        if (dest == null || !dest.matches("[0-9a-fA-F]{32}")) return;
        String fp = fingerprint == null ? "" : fingerprint;
        if (fp.isEmpty()) {
            JSONObject st = currentStatus();
            JSONArray exits = st == null ? null : st.optJSONArray("exits");
            for (int i = 0; exits != null && i < exits.length(); i++) {
                JSONObject e = exits.optJSONObject(i);
                if (e != null && dest.equals(e.optString("d"))) { fp = e.optString("id", ""); break; }
            }
        }
        Intent in = new Intent(this, NodeAdminActivity.class)
                .putExtra(NodeAdminActivity.EXTRA_TARGET, dest)
                .putExtra(NodeAdminActivity.EXTRA_NAME, name == null ? "Нода" : name)
                .putExtra(NodeAdminActivity.EXTRA_FINGERPRINT, fp);
        startActivity(in);
    }
}
