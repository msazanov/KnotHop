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
import android.widget.SeekBar;
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

    private LinearLayout pairBox, mainBox, adminBox, usersBox;
    private TextView usersTitle;
    private EditText profileField;
    private TextView pairMsg, header, status, usersView, nodesMsg, updMsg;
    private Button benchBtn;
    private TextView pullHint, modeText;
    private LogConsole logConsole;
    private SeekBar modeSeek;
    private boolean modeDragging;
    /** Выбранный пользователем режим, пока служба его не подтвердила (через ~5 с ползунок снова показывает фактический). */
    private int pendingMode = -1;
    private long pendingUntil;
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
        PullScrollView sv = new PullScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 48, 24, 24);
        sv.addView(root);
        pullHint = new TextView(this);
        pullHint.setGravity(Gravity.CENTER);
        pullHint.setTextSize(13);
        pullHint.setVisibility(View.GONE);
        root.addView(pullHint);
        sv.setListener(new PullScrollView.Listener() {
            @Override public void onPull(float f) {
                pullHint.setVisibility(f > 0 ? View.VISIBLE : View.GONE);
                pullHint.setText(f >= 1f ? "Отпустите, чтобы обновить" : "Потяните вниз, чтобы обновить");
            }
            @Override public void onRefresh() { pullRefresh(); }
            @Override public void onPullUp() { logConsole.setOpen(true); }
        });

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
            Ui.tick(v);
            ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData d = cb.getPrimaryClip();
            if (d != null && d.getItemCount() > 0 && d.getItemAt(0).getText() != null) profileField.setText(d.getItemAt(0).getText());
        });
        Button pair = new Button(this);
        pair.setText("Спарить");
        pair.setFilterTouchesWhenObscured(true);   // F8
        pair.setOnClickListener(v -> { Ui.tick(v); doPair(profileField.getText().toString()); });
        row.addView(paste);
        row.addView(pair);
        pairBox.addView(row);
        Button scan = new Button(this);
        scan.setText("Сканировать QR");
        scan.setOnClickListener(v -> { Ui.tick(v); startActivityForResult(new Intent(this, ScanActivity.class), REQ_SCAN); });
        pairBox.addView(scan);
        Button own = new Button(this);
        own.setText("Своя сеть (нужна собственная серверная нода)");
        own.setOnClickListener(v -> { Ui.tick(v); doPair(""); });
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
        nodesMsg = new LogText(this, "ноды");
        mainBox.addView(nodesMsg);
        updMsg = new LogText(this, "версия");
        updMsg.setText("Версия " + installedName() + " (" + installedCode() + ")");
        mainBox.addView(updMsg);
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
        inviteBtn.setOnClickListener(v -> { Ui.tick(v); startActivity(new Intent(this, InviteActivity.class)); });
        adminBox.addView(inviteBtn);
        usersView = new TextView(this);
        usersView.setTextSize(12);
        adminBox.addView(usersView);
        usersTitle = new TextView(this);
        usersTitle.setTypeface(Typeface.DEFAULT_BOLD);
        usersTitle.setPadding(0, 16, 0, 4);
        adminBox.addView(usersTitle);
        usersBox = new LinearLayout(this);
        usersBox.setOrientation(LinearLayout.VERTICAL);
        adminBox.addView(usersBox);
        mainBox.addView(adminBox);
        status = new TextView(this);
        status.setTextSize(13);
        status.setTypeface(Typeface.MONOSPACE);
        mainBox.addView(status);
        topo = new TopologyView(this);
        topo.setOnPick((dest, name) -> toggleDefaultExit(dest, name));   // короткий тап: нода по умолчанию
        topo.setOnLongPick((dest, name) -> openNodeAdmin(dest, name, ""));   // удержание: настройки ноды
        topo.setOnPhonePick(() -> startActivity(new Intent(this, MyNodeActivity.class)));
        mainBox.addView(topo, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 600));
        android.widget.CheckBox pingBox = new android.widget.CheckBox(this);
        pingBox.setText("Расстояние по пингу (меньше пинг — ближе)");
        pingBox.setTextSize(13);
        pingBox.setChecked(sp.getBoolean("ping_layout", false));
        topo.setPingMode(pingBox.isChecked());
        pingBox.setOnCheckedChangeListener((v, on) -> { sp.edit().putBoolean("ping_layout", on).apply(); topo.setPingMode(on); });
        mainBox.addView(pingBox);
        android.widget.CheckBox debugBox = new android.widget.CheckBox(this);
        debugBox.setText("Отладка (расширенный журнал)");
        debugBox.setTextSize(13);
        debugBox.setChecked(Util.debug);
        Button shareLog = new Button(this);
        shareLog.setText("Поделиться журналом");
        shareLog.setVisibility(Util.debug ? View.VISIBLE : View.GONE);
        shareLog.setOnClickListener(v -> { Ui.tick(v); shareLog(); });
        debugBox.setOnCheckedChangeListener((v, on) -> {
            sp.edit().putBoolean("debug", on).apply();
            Util.setDebug(on);
            shareLog.setVisibility(on ? View.VISIBLE : View.GONE);
            Util.log(on ? "отладка включена: в журнал пишутся снимки состояния, причины обрывов, паузы процесса" : "отладка выключена");
        });
        mainBox.addView(debugBox);
        mainBox.addView(shareLog);
        benchBtn = new Button(this);
        benchBtn.setText("Обновить и проверить");
        benchBtn.setOnClickListener(v -> { Ui.tick(v); refreshAndTest(); });
        mainBox.addView(benchBtn);
        benchView = new TextView(this);
        benchView.setTextSize(12);
        benchView.setTypeface(Typeface.MONOSPACE);
        mainBox.addView(benchView);
        root.addView(mainBox);

        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        outer.addView(sv, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        logConsole = new LogConsole(this);
        outer.addView(logConsole, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        LinearLayout modePanel = buildModePanel();
        outer.addView(modePanel, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        setContentView(outer);
        // клавиатура (поле фильтра журнала): журнал занимает всё место от верха экрана до клавиатуры, остальное прячется
        final View decor = getWindow().getDecorView();
        decor.getViewTreeObserver().addOnGlobalLayoutListener(() -> {
            android.graphics.Rect r = new android.graphics.Rect();
            decor.getWindowVisibleDisplayFrame(r);
            int full = decor.getRootView().getHeight();
            boolean kb = full > 0 && full - r.bottom > full * 0.15f;
            logConsole.setMaxBody((int) (full * 0.6f));
            boolean grow = kb && logConsole.isOpen();
            logConsole.setExpanded(grow);
            sv.setVisibility(grow ? View.GONE : View.VISIBLE);
            modePanel.setVisibility(grow ? View.GONE : View.VISIBLE);
        });
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != 0) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2);
        }
        handleLink(getIntent());
        handleLabIntent(getIntent());
        // после показа экрана, в фоновом потоке: старт приложения от сети не зависит
        if (b == null && !Util.LAB_BUILD) ui.postDelayed(() -> checkUpdate(false), 2000);
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
        if (!sp.contains("profile")) offerShown = "";   // профиль мог быть забыт на экране своей ноды
        topo.setActive(true);
        Util.dbg("экран открыт");
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        super.onPause();
        topo.setActive(false);
        Util.dbg("экран закрыт");
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

    private AlertDialog nameDialog;

    /**
     * Имя телефона для сети (state/node-name.txt, его нативная часть сообщает выходам в T_USE). Спрашиваем один раз, пока имя - автоимя
     * «телефон-XXXXXX» (по хешу ключа) или не задано; позже имя меняется в настройках своей ноды.
     */
    private void maybeAskName() {
        if (sp.getBoolean("name_asked", false) || (nameDialog != null && nameDialog.isShowing())) return;
        if (offerDialog != null && offerDialog.isShowing()) return;
        if (!NodeName.isAuto(getFilesDir())) { sp.edit().putBoolean("name_asked", true).apply(); return; }
        nameDialog = NodeName.dialog(this, getFilesDir(), () -> sp.edit().putBoolean("name_asked", true).apply());
    }

    private static final String[] MODE_TITLE = {"Отключено", "В сети нод, без VPN", "VPN включён"};

    /** Закреплённая внизу панель: ползунок с тремя точками притяжения (слева - отключено, середина - сеть нод без VPN, справа - VPN). */
    private LinearLayout buildModePanel() {
        LinearLayout p = new LinearLayout(this);
        p.setOrientation(LinearLayout.VERTICAL);
        p.setBackgroundColor(Ui.panel(this));
        p.setPadding(32, 16, 32, 24);
        modeText = new TextView(this);
        modeText.setTextSize(14);
        modeText.setTypeface(Typeface.DEFAULT_BOLD);
        modeText.setGravity(Gravity.CENTER);
        p.addView(modeText);
        modeSeek = new SeekBar(this);
        modeSeek.setMax(100);
        modeSeek.setFilterTouchesWhenObscured(true);   // F8
        modeSeek.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
            private int lastStep;
            @Override public void onProgressChanged(SeekBar s, int v, boolean fromUser) {
                if (!fromUser) return;
                int step = (v + 25) / 50;
                modeText.setText(MODE_TITLE[step]);
                if (step != lastStep) { Ui.tick(s); lastStep = step; }
            }
            @Override public void onStartTrackingTouch(SeekBar s) { modeDragging = true; lastStep = (s.getProgress() + 25) / 50; }
            @Override public void onStopTrackingTouch(SeekBar s) {
                modeDragging = false;
                int m = (s.getProgress() + 25) / 50;
                s.setProgress(m * 50, true);   // точка притяжения
                applyMode(m);
            }
        });
        p.addView(modeSeek);
        LinearLayout labels = new LinearLayout(this);
        labels.setOrientation(LinearLayout.HORIZONTAL);
        String[] t = {"Откл.", "Сеть", "VPN"};
        int[] g = {Gravity.START, Gravity.CENTER_HORIZONTAL, Gravity.END};
        for (int i = 0; i < 3; i++) {
            TextView l = new TextView(this);
            l.setText(t[i]);
            l.setTextSize(12);
            l.setGravity(g[i]);
            labels.addView(l, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        }
        p.addView(labels);
        return p;
    }

    /** Фактический режим: 0 - служба не работает, 1 - узел в сети без TUN, 2 - VPN (сбой с удержанием TUN тоже считается режимом 2). */
    private int curMode() {
        if (pendingMode >= 0 && System.currentTimeMillis() < pendingUntil) return pendingMode;
        pendingMode = -1;
        if (KnotHopVpnService.tunHeld) return 2;
        if (!active()) return 0;
        return KnotHopVpnService.mode == 2 ? 2 : 1;
    }

    private void updateModePanel() {
        if (modeSeek == null || modeDragging) return;
        int m = curMode();
        if (modeSeek.getProgress() != m * 50) modeSeek.setProgress(m * 50);
        String t = MODE_TITLE[m];
        if (KnotHopVpnService.tunHeld) t = "VPN не работает, трафик заблокирован: сдвиньте влево до конца";
        else if (!KnotHopVpnService.lastError.isEmpty() && m != 0) t += " (" + KnotHopVpnService.lastError + ")";
        modeText.setText(t);
    }

    private void applyMode(int m) {
        int cur = curMode();
        if (m == cur) return;
        Ui.click(modeSeek);
        if (KnotHopVpnService.tunHeld && m != 0) {
            android.widget.Toast.makeText(this, "Сначала сдвиньте ползунок влево до конца, затем включите заново", android.widget.Toast.LENGTH_LONG).show();
            updateModePanel();
            return;
        }
        pendingMode = m;
        pendingUntil = System.currentTimeMillis() + 5000;
        if (m == 0) {
            startService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_STOP));
            return;
        }
        if (m == 2) {
            Intent consent = VpnService.prepare(this);
            if (consent != null) {
                pendingUntil = System.currentTimeMillis() + 60_000;   // пока открыт системный диалог
                startActivityForResult(consent, REQ_VPN);
                return;
            }
        }
        sendMode(m);
    }

    private void sendMode(int m) {
        startForegroundService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_MODE).putExtra(KnotHopVpnService.EXTRA_MODE, m));
    }

    /**
     * Потяни-чтобы-обновить: права и список нод (расписки), внеочередной анонс, проверка связи со всеми нодами, обновление скачанных
     * списков маршрутов, если они старше суток. Нужен включённый режим «Сеть» или «VPN»: узел работает только в них.
     */
    private TextView geoMsg;
    private volatile boolean geoBusy;

    private void pullRefresh() {
        checkUpdate(true);
        refreshGeo();
        if (!active()) {
            android.widget.Toast.makeText(this, "Геоданные и версия проверяются. Для опроса нод включите «Сеть» или «VPN»", android.widget.Toast.LENGTH_SHORT).show();
            return;
        }
        refreshNodes();
        Native.kick(0);
        Native.kick(1);
    }

    private long lastManualAnnounce;

    /**
     * Единая кнопка: проверка версии и геоданных, опрос нод и прав, ручной анонс себя, проверка связи с нодами и замер скорости.
     * Анонс не чаще раза в минуту (штатный период 600 с остаётся; это просьба пользователя, а не частый цикл). Первый замер скорости
     * спрашивает подтверждение (HTTP не шифруется), дальше берутся сохранённые адреса.
     */
    private void refreshAndTest() {
        checkUpdate(true);
        refreshGeo();
        if (!active()) {
            android.widget.Toast.makeText(this, "Геоданные и версия проверяются. Для опроса нод и замера скорости включите «Сеть» или «VPN»", android.widget.Toast.LENGTH_SHORT).show();
            return;
        }
        refreshNodes();
        long now = android.os.SystemClock.elapsedRealtime();
        if (lastManualAnnounce == 0 || now - lastManualAnnounce >= 60_000) {
            lastManualAnnounce = now;
            Native.kick(0);
        }
        Native.kick(1);
        if (!"up".equals(KnotHopVpnService.phase)) return;   // замер идёт только через включённый VPN
        if (sp.getBoolean("speed_ack", false) && KnotHopVpnService.speedPath() != null) requestBench(25);
        else confirmBench();
    }

    private void refreshGeo() {
        if (geoBusy) return;
        geoBusy = true;
        if (geoMsg == null) {
            geoMsg = new LogText(this, "геоданные");
            mainBox.addView(geoMsg, Math.min(2, mainBox.getChildCount()));
        }
        geoMsg.setText("Проверяю геоданные…");
        final File files = getFilesDir();
        final File rstate = new File(files, "rstate");
        new Thread(() -> {
            String err = RulesFiles.download(files, t -> ui.post(() -> { if (!isFinishing() && !isDestroyed()) geoMsg.setText(t); }));
            if (err.isEmpty()) {
                rstate.mkdirs();
                try {
                    if (Native.runVpn("rules-list --state " + rstate.getAbsolutePath(), rstate.getAbsolutePath()) != 0) err = "не удалось разобрать геоданные";
                } catch (Throwable t) { err = "не удалось разобрать геоданные"; }
            }
            final String result = err;
            ui.post(() -> {
                geoBusy = false;
                if (!isFinishing() && !isDestroyed()) geoMsg.setText(result.isEmpty() ? "Геоданные актуальны. Исключения из VPN применяются при следующем подключении" : "Геоданные: " + result);
            });
        }, "knothop-rules-refresh").start();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_VPN) {
            if (res == RESULT_OK) sendMode(2);
            else { pendingMode = -1; updateModePanel(); }
        }
        if (req == REQ_SCAN && res == RESULT_OK && data != null) {
            String t = data.getStringExtra(ScanActivity.EXTRA_TEXT);
            if (t != null) {
                profileField.setText(t);
                pairMsg.setText("QR считан. Проверьте и нажмите «Спарить»");
            }
        }
    }

    /** Выбор выхода: файл select в каталоге состояния читает нативная часть. Без выбора (или пока выбранный выход недоступен) нативная часть сама берёт лучший. */
    private void select(String dest) {
        try {
            File st = new File(getFilesDir(), "state");
            st.mkdirs();
            java.nio.file.Files.write(new File(st, "select").toPath(), dest.getBytes("UTF-8"));
        } catch (Exception ignored) { }
    }

    /** Короткий тап по ноде: сделать её выходом по умолчанию; повторный тап по выбранной возвращает автоматический выбор. */
    private void toggleDefaultExit(String dest, String name) {
        if (dest == null || !dest.matches("[0-9a-fA-F]{32}")) return;
        String d = dest.toLowerCase(java.util.Locale.ROOT);
        File st = new File(getFilesDir(), "state");
        boolean same = d.equals(Util.read(new File(st, "select")).trim().toLowerCase(java.util.Locale.ROOT));
        Util.dbg("тап по ноде " + name + (same ? ": выход - авто" : ": выход по умолчанию"));
        try {
            st.mkdirs();
            File tmp = new File(st, "select.tmp");
            java.nio.file.Files.write(tmp.toPath(), (same ? "auto" : d).getBytes("UTF-8"));
            java.nio.file.Files.move(tmp.toPath(), new File(st, "select").toPath(), java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            android.widget.Toast.makeText(this, same ? "Выход выбирается автоматически" : "Выход по умолчанию: " + TopologyView.shortName(name == null ? "" : name)
                    + " (подключение зависит от прав и доступности)", android.widget.Toast.LENGTH_SHORT).show();
        } catch (Exception e) { android.widget.Toast.makeText(this, "Не удалось сохранить выбор", android.widget.Toast.LENGTH_LONG).show(); }
    }

    private long nodesRefreshSerial;

    /** Каталог запрашивается отдельно от расписок приглашения. Работает и в режиме «Сеть», после полной выдачи и истечения билета. */
    private void refreshNodes() {
        if (!(active() || KnotHopVpnService.tunHeld)) {
            android.widget.Toast.makeText(this, "Сначала включите режим «Сеть» или «VPN»", android.widget.Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            File st = new File(getFilesDir(), "state");
            st.mkdirs();
            final File result = new File(st, "refresh-result.txt");
            final File directory = new File(st, "directory-result.json");
            final long started = System.currentTimeMillis();
            final long serial = ++nodesRefreshSerial;
            result.delete();
            new File(st, "refresh-nodes").createNewFile();
            nodesMsg.setVisibility(View.VISIBLE);
            nodesMsg.setText("Запрашиваю каталог нод и проверяю права…");
            final long until = android.os.SystemClock.elapsedRealtime() + 180_000;
            ui.postDelayed(new Runnable() {
                public void run() {
                    if (isFinishing() || isDestroyed() || serial != nodesRefreshSerial) return;
                    String r = result.exists() ? Util.read(result).trim() : "";
                    String catalog = "";
                    try {
                        JSONObject d = new JSONObject(Util.read(directory));
                        JSONObject current = currentStatus();
                        JSONArray exits = current == null ? null : current.optJSONArray("exits");
                        if (d.optLong("at_ms", 0) >= started) catalog = "Каталог обновлён: " + d.optInt("entries", 0)
                                + " нод; выходов с подтверждёнными правами: " + (exits == null ? d.optInt("known", 0) : exits.length());
                    } catch (Exception ignored) { }
                    if (!catalog.isEmpty()) nodesMsg.setText(catalog + (r.isEmpty() ? "" : "\n" + r));
                    else if (!r.isEmpty()) nodesMsg.setText(r);
                    if (android.os.SystemClock.elapsedRealtime() <= until) ui.postDelayed(this, 1000);
                    else if (catalog.isEmpty()) nodesMsg.setText((r.isEmpty() ? "" : r + "\n") + "Свежий каталог пока не получен. Повторите жест позже");
                }
            }, 1000);
        } catch (Exception e) { nodesMsg.setText("Не удалось запустить обновление нод (" + e.getClass().getSimpleName() + ")"); }
    }

    private long installedCode() {
        try {
            android.content.pm.PackageInfo pi = getPackageManager().getPackageInfo(getPackageName(), 0);
            return Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : pi.versionCode;
        } catch (Exception e) { return 0; }
    }

    private String installedName() {
        try { return getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception e) { return "?"; }
    }

    private static final long UPDATE_EVERY_MS = 12L * 3600 * 1000;

    /**
     * Свежий релиз на GitHub. Автоматически: при запуске, не чаще раза в 12 часов, молча, если нечего предлагать или нет сети; одну и ту же версию
     * после «Позже» повторно не предлагаем. Вручную (кнопка): всегда отвечает. Запрос идёт в фоновом потоке, старт экрана не ждёт.
     */
    private void checkUpdate(final boolean manual) {
        if (isFinishing() || isDestroyed()) return;
        long now = System.currentTimeMillis();
        if (!manual && now - sp.getLong("upd_ts", 0) < UPDATE_EVERY_MS) return;
        if (manual) updMsg.setText("Проверяю…");
        final long have = installedCode();
        UpdateCheck.run(r -> ui.post(() -> {
            if (isFinishing() || isDestroyed()) return;
            if (r.error != null) {
                if (manual) { updMsg.setText("Не удалось проверить: " + r.error); }
                return;
            }
            sp.edit().putLong("upd_ts", System.currentTimeMillis()).apply();
            if (r.latest <= have) {
                if (manual) updMsg.setText("Установлена последняя версия " + installedName() + " (" + have + ")");
                return;
            }
            updMsg.setText("Доступна версия " + r.tag + " (у вас " + installedName() + ", " + have + ")");
            if (!manual && sp.getLong("upd_dismissed", 0) >= r.latest) return;
            new AlertDialog.Builder(this).setTitle("Доступно обновление")
                .setMessage("Вышла версия " + r.tag + ", у вас " + installedName() + ".\nСкачать APK? После загрузки откройте файл и подтвердите установку поверх: профиль и права сохранятся.")
                .setPositiveButton("Скачать", (d, w) -> {
                    try { startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(UpdateCheck.APK))); }
                    catch (Exception e) { android.widget.Toast.makeText(this, "Нет приложения для открытия ссылки", android.widget.Toast.LENGTH_LONG).show(); }
                })
                .setNegativeButton("Позже", (d, w) -> sp.edit().putLong("upd_dismissed", r.latest).apply())
                .show();
        }));
    }

    private final Runnable tick = new Runnable() {
        public void run() {
            refresh();
            pollOffer();
            if (sp.contains("profile") && !Util.LAB_BUILD) maybeAskName();
            ui.postDelayed(this, 1000);
        }
    };

    private static String mb(long b) {
        return String.format("%.1f МБ", b / 1e6);
    }

    /** Текст, которого на экране нет: всё, что в него пишут, попадает в журнал приложения (консоль внизу). */
    private final class LogText extends TextView {
        private String tag;
        private String last = "";
        LogText(Context c, String tag) {
            super(c);
            this.tag = tag;
            super.setVisibility(View.GONE);
        }
        @Override public void setText(CharSequence t, BufferType type) {
            super.setText(t, type);
            if (tag == null || t == null) return;
            String v = t.toString();
            if (v.isEmpty() || v.equals(last)) return;
            last = v;
            Util.log(tag + ": " + v);
        }
        @Override public void setVisibility(int v) { /* всегда скрыт */ }
    }

    /** Отправить журнал (нативный и приложения, без профиля, ключей и приглашений) по действию пользователя: хвост до 150 КБ. */
    private void shareLog() {
        String[] ls = Util.mergedLog(Util.read(new File(new File(getFilesDir(), "state"), "log.txt")));
        StringBuilder b = new StringBuilder("KnotHop " + installedName() + " (" + installedCode() + "), Android " + android.os.Build.VERSION.SDK_INT + " " + android.os.Build.MODEL + "\n");
        int from = ls.length;
        int size = 0;
        while (from > 0 && size < 150_000) size += ls[--from].length() + 1;
        for (int i = from; i < ls.length; i++) b.append(ls[i]).append('\n');
        Intent in = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, b.toString()).putExtra(Intent.EXTRA_SUBJECT, "Журнал KnotHop");
        startActivity(Intent.createChooser(in, "Поделиться журналом"));
    }

    private final java.util.Map<String, String> loggedOnce = new java.util.HashMap<>();

    /** В журнал только при изменении значения (экран обновляется раз в секунду). */
    private void logChange(String key, String val) {
        if (val == null || val.isEmpty() || val.equals(loggedOnce.get(key))) return;
        loggedOnce.put(key, val);
        Util.log(key + ": " + val.replace('\n', ' '));
    }

    /** Заголовок виден, только если от пользователя нужно действие; остальное уходит в журнал. */
    private void showHeader(String text, boolean action) {
        if (action) {
            header.setText(text);
            header.setVisibility(View.VISIBLE);
        } else {
            header.setVisibility(View.GONE);
            logChange("заголовок", text);
        }
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
            if (pr.own()) refreshUsers();
            if (pr.own()) showHeader("Вы администратор своей сети. Для первой настройки привяжите корень телефона к своей серверной ноде командой knothopd trust-anchor на сервере. "
                    + "Для выпуска приглашения включите «Сеть» и выберите ноды в «Пригласить»; VPN не обязателен. QR готов сразу, разрешения доставляются в фоне. Приглашение одноразовое, действует 48 часов. Оставьте «Сеть» включённой для доставки", false);
            else if (enrolled()) showHeader(grantedHeader(), false);
            else showHeader("Приглашение принято, зачисление ещё не завершено. Передвиньте ползунок внизу в «Сеть» или «VPN»: телефон свяжется с нодами приглашения и покажет, какие права вам предлагают; согласитесь в диалоге", true);
        } catch (Throwable e) {
            showHeader("профиль повреждён: " + e.getMessage(), true);
        }
        updateModePanel();
        // Верх экрана: что происходит сейчас, активное соединение, скорость. Остальное - в журнал (консоль внизу).
        String phase = KnotHopVpnService.phase;
        logChange("состояние", phase);
        String doing = null, conn = null, speed = null;
        if (!KnotHopVpnService.lastError.isEmpty()) doing = "ОШИБКА: " + KnotHopVpnService.lastError;
        File state = new File(getFilesDir(), "state");
        JSONObject j = null;
        try {
            String js = Util.read(new File(state, "status.json"));
            if (!js.isEmpty() && active()) j = new JSONObject(js);
        } catch (Throwable ignored) { }
        if (j != null) {
            try {
                JSONObject cur = j.optJSONObject("current");
                String pinned = j.optString("selected");
                String st = j.optString("status");
                logChange("статус", st);
                if (doing == null && !st.isEmpty() && !st.startsWith("выход:")) doing = st;   // «подключаюсь к …», «выбранный выход недоступен …»
                if (cur != null) {
                    StringBuilder c = new StringBuilder("выход: ").append(TopologyView.shortName(cur.optString("n")));
                    if (pinned.equalsIgnoreCase(cur.optString("d"))) c.append("  ★");
                    if (!cur.isNull("via")) {
                        String vd = cur.optString("via"); String vn = vd;
                        JSONArray exs = j.optJSONArray("exits");
                        for (int q = 0; exs != null && q < exs.length(); q++) if (vd.equals(exs.optJSONObject(q).optString("d"))) vn = TopologyView.shortName(exs.optJSONObject(q).optString("n"));
                        c.append("  через ").append(vn);
                    }
                    c.append("  · ").append(TopologyView.carrierName(cur.optString("carrier")));
                    conn = c.toString();
                    logChange("соединение", conn + " (носитель - открытый сокет, не путь RNS)");
                } else if (doing == null) {
                    doing = "ищу выход…";
                }
                if (pinned.matches("[0-9a-fA-F]{32}") && (cur == null || !pinned.equalsIgnoreCase(cur.optString("d")))) logChange("выбор", "выбран вами " + pinned.substring(0, 8) + ", подключаюсь");
                updateBenchUi(state, j, cur);
                JSONObject t = j.getJSONObject("tun");
                long up = t.getLong("from_tun_bytes"), down = t.getLong("to_tun_bytes"), sts = j.getLong("ts_ms");
                if (prevTs != 0 && sts > prevTs) {
                    double dt = (sts - prevTs) / 1000.0;
                    rUp = (up - prevUp) * 8 / dt / 1e6;
                    rDown = (down - prevDown) * 8 / dt / 1e6;
                }
                if (sts != prevTs) { prevUp = up; prevDown = down; prevTs = sts; }
                speed = String.format("↑ %.1f Мбит/с (%s)   ↓ %.1f Мбит/с (%s)", rUp, mb(up), rDown, mb(down));
                JSONArray us = j.optJSONArray("users");
                StringBuilder ut = new StringBuilder();
                for (int q = 0; us != null && q < us.length(); q++) ut.append(q == 0 ? "" : ", ").append(us.optJSONObject(q).optString("h"));
                usersView.setText(ut.length() == 0 ? "" : "Зачислены с этого запуска: " + ut);
                topo.update(j);
                JSONArray lt = j.optJSONArray("log_tail");
                if (lt != null) for (int q = lt.length() - 1; q >= 0; q--) { String ln = lt.optString(q); if (logSeen.add(ln)) Util.lab("NLOG " + ln); }
                buildList(j);
            } catch (Throwable e) {
                doing = "статус: " + e;
            }
        } else {
            prevTs = 0;
            rUp = rDown = 0;
            try { topo.update(new JSONObject("{\"state\":\"idle\",\"ip\":\"\"}")); } catch (Exception ignored) { }
            updateBenchUi(state, null, null);
            if (doing == null) doing = "idle".equals(phase) ? "VPN выключен" : "состояние: " + phase;
        }
        StringBuilder s = new StringBuilder();
        if (doing != null) s.append(doing).append('\n');
        if (conn != null) s.append(conn).append('\n');
        if (speed != null) s.append(speed).append('\n');
        if (s.length() > 0) s.setLength(s.length() - 1);
        status.setText(s);
        Util.lab("STATUS " + s.toString().replace("\n", " | "));
        String log = Util.read(new File(state, "log.txt"));
        String[] lines = Util.mergedLog(log);
        logConsole.setLines(lines);
        if (lines.length > 0) Util.lab("LOG " + lines[lines.length - 1]);
    }

    private void confirmBench() {
        if (KnotHopVpnService.speedPath() == null) {
            new AlertDialog.Builder(this).setMessage("Тест требует включённый режим «VPN» (ползунок справа) и готовый выход. Сокеты теста идут только через туннель." + (KnotHopVpnService.speedWhy.isEmpty() ? "" : "\n\nПричина: " + KnotHopVpnService.speedWhy)).setPositiveButton("OK", null).show();
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
                    sp.edit().putBoolean("speed_ack", true).apply();
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
        benchBtn.setEnabled(!SpeedTest.running());
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

    /** Узлы выходов нужны правилам маршрутизации (имена, назначения); сам список на экране убран: ноды выбираются тапом по графу. */
    private void buildList(JSONObject j) {
        JSONArray ex = j.optJSONArray("exits");
        if (ex != null) RoutingCfg.cacheNodes(getFilesDir(), ex);
    }

    // --- админ: пользователи своей сети. Список - из локального Trust (trust-view), а не из анонсов: телефоны с одним USE не анонсируются.
    private JSONObject usersView0;
    private String usersSig = "";
    private long usersAt;
    private boolean usersBusy;

    private void refreshUsers() {
        long now = android.os.SystemClock.elapsedRealtime();
        if (usersBusy || now - usersAt < 4000) return;
        usersBusy = true;
        usersAt = now;
        final File st = new File(getFilesDir(), "state");
        new Thread(() -> {
            JSONObject got = null;
            try {
                String raw = Native.runCLI("trust-view --state " + st.getAbsolutePath(), st.getAbsolutePath());
                if (raw != null && raw.length() <= 65536) {
                    JSONObject v = new JSONObject(raw);
                    if (!v.has("error")) got = v;
                }
            } catch (Throwable ignored) { }
            final JSONObject result = got;
            runOnUiThread(() -> {
                usersBusy = false;
                if (isFinishing() || isDestroyed()) return;
                renderUsers(result, st);
            });
        }, "knothop-users-view").start();
    }

    private java.util.Map<String, String> knownNames() {
        java.util.Map<String, String> m = new java.util.HashMap<>();
        JSONObject j = currentStatus();
        JSONArray ex = j == null ? null : j.optJSONArray("exits");
        for (int i = 0; ex != null && i < ex.length(); i++) {
            JSONObject e = ex.optJSONObject(i);
            String id = e == null ? "" : e.optString("id", "").toLowerCase(java.util.Locale.ROOT);
            if (id.matches("[0-9a-f]{32}")) m.put(id, RightsEditor.clip(TopologyView.shortName(e.optString("n", "?"))));
        }
        return m;
    }

    private void renderUsers(JSONObject view, File st) {
        JSONArray ps = view == null ? null : view.optJSONArray("participants");
        java.util.Map<String, String> names = knownNames();
        String sig = String.valueOf(view) + names;
        if (sig.equals(usersSig)) return;
        usersSig = sig;
        usersView0 = view;
        usersBox.removeAllViews();
        int n = ps == null ? 0 : ps.length();
        boolean manage = view != null && (view.optBoolean("can_add", false) || view.optBoolean("can_remove", false));
        usersTitle.setText(view == null ? "Пользователи: состояние доверия недоступно" : "Пользователи (" + n + ")" + (manage ? " — удерживайте строку, чтобы изменить права" : ""));
        for (int i = 0; ps != null && i < ps.length(); i++) {
            JSONObject p = ps.optJSONObject(i);
            String holder = p == null ? "" : p.optString("holder", "");
            if (!holder.matches("[0-9a-f]{32}")) continue;
            final String name = names.get(holder);
            final int rights = p.optInt("rights", 0) & RightsEditor.ALL, eff = p.optInt("eff", rights) & RightsEditor.ALL;
            TextView tv = new TextView(this);
            tv.setTextSize(14);
            tv.setPadding(12, 18, 12, 18);
            tv.setText((name == null ? "Пользователь" : name) + "  ·  " + NodeAdminActivity.brief(holder) + "\n" + RightsEditor.rightsText(rights)
                    + (eff != rights ? " (действует: " + RightsEditor.rightsText(eff) + ")" : "") + (p.has("queued") ? "\nв очереди: " + RightsEditor.rightsText(p.optInt("queued", 0) & RightsEditor.ALL) : ""));
            tv.setClickable(true);
            tv.setOnClickListener(v -> android.widget.Toast.makeText(this, manage ? "Удерживайте, чтобы изменить права" : "Права только для просмотра", android.widget.Toast.LENGTH_SHORT).show());
            if (manage) tv.setOnLongClickListener(v -> {
                Ui.tick(v);
                RightsEditor.edit(this, usersView0, st, holder, name, rights,
                        msg -> android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show(),
                        () -> { usersSig = ""; usersAt = 0; refreshUsers(); });
                return true;
            });
            usersBox.addView(tv);
        }
        if (n == 0 && view != null) {
            TextView tv = new TextView(this);
            tv.setTextSize(12);
            tv.setText("Пока никого: выпустите приглашение кнопкой «Пригласить».");
            usersBox.addView(tv);
        }
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
        Intent in = new Intent(this, NodeSettingsActivity.class)
                .putExtra(NodeAdminActivity.EXTRA_TARGET, dest)
                .putExtra(NodeAdminActivity.EXTRA_NAME, name == null ? "Нода" : name)
                .putExtra(NodeAdminActivity.EXTRA_FINGERPRINT, fp);
        startActivity(in);
    }
}
