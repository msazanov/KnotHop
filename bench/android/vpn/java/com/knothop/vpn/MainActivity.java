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
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * KnotHop VPN. Главный экран сразу (ключ ноды создаётся при запуске; профиля и экрана «Вход в сеть» нет - любая нода сама себе админ): карточки
 * (состояние, граф выходов, маршрутизация, «Сеть и приглашения» с кнопкой «Вступить»), закреплённый внизу переключатель режимов, шторка журнала
 * с диагностикой (жест: удержать и протянуть вверх) и обновление потягиванием вниз.
 */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private SharedPreferences sp;

    private LinearLayout mainBox, adminBox;
    private TextView header, status, nodesMsg, updMsg, updView, directWarn, routingSummary, topStatus;
    private LinearLayout stateCard;
    /** Из status.json для верхней строки состояния: число известных нод и имя текущего выхода. */
    private int nodeCount;
    /** P2P-контакты без ролей: сколько всего, с выбранным QUIC-путём и с окончательным отказом. */
    private int p2pConnected, p2pTotal, p2pFailed;
    private String exitName = "";
    private AppUpdater updater;
    private TextView pullHint, modeText;
    private LogConsole logConsole;
    private ModeSlider modeSlider;
    private LinearLayout modePanel;
    /** Выбранный пользователем режим, пока служба его не подтвердила (через ~5 с ползунок снова показывает фактический). */
    private int pendingMode = -1;
    private long pendingUntil;
    private TextView benchView;
    /** Предел длины вставляемого или открытого по ссылке приглашения (H4/O6). */
    private static final int MAX_PASTE = 4096;
    private static final String[] RIGHTS_TEXT = {"пользоваться сетью", "пропускать транзит", "быть выходом в интернет", "зачислять новых", "отзывать права", "менять настройки сети"};
    /** Нет ни одной ноды с правом выхода (по свежему статусу): отсчёт непрерывного состояния, чтобы не мигать при запуске. */
    private long noExitsSince;
    private TextView exitsNote;
    private View noExitHelp;
    /** Ожидающие погашения пары (view.pending): их число обновляет фоновый опрос. */
    private volatile int pendWaiting, pendTotal;
    private long pendPollAt;
    private TopologyView topo;
    private LinearLayout nodeRows;
    private String nodeRowsKey = "";
    private long prevTs, prevUp, prevDown;
    private double rUp, rDown;

    private int dp(float v) { return Ui.dp(this, v); }

    private LinearLayout.LayoutParams lpMatch(int top) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(top);
        return lp;
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        sp = getSharedPreferences("p", MODE_PRIVATE);
        PullScrollView sv = new PullScrollView(this);
        sv.setVerticalScrollBarEnabled(false);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(12), dp(16), dp(72));   // снизу запас под ручку журнала
        sv.addView(root);
        pullHint = Ui.text(this, "", 13, Ui.ORANGE, true);
        pullHint.setGravity(Gravity.CENTER);
        pullHint.setVisibility(View.GONE);
        sv.setListener(new PullScrollView.Listener() {
            @Override public void onPull(float f) {
                pullHint.setVisibility(f > 0 ? View.VISIBLE : View.GONE);
                pullHint.setText(f >= 1f ? "Отпустите, чтобы обновить" : "Потяните вниз, чтобы обновить");
            }
            @Override public void onRefresh() { pullRefresh(); }
        });

        // --- главный экран
        mainBox = new LinearLayout(this);
        mainBox.setOrientation(LinearLayout.VERTICAL);
        mainBox.setVisibility(View.VISIBLE);
        updView = Ui.text(this, "Версия " + installedName() + " (" + installedCode() + ")", 11, Ui.MUTED, false);
        updView.setGravity(Gravity.CENTER);
        header = Ui.text(this, "", 13, Ui.ORANGE, false);
        header.setVisibility(View.GONE);
        header.setPadding(0, dp(8), 0, 0);
        mainBox.addView(header);
        nodesMsg = new LogText(this, "ноды");
        mainBox.addView(nodesMsg);
        updMsg = new LogText(this, "версия");
        updMsg.setText("Версия " + installedName() + " (" + installedCode() + ")");
        mainBox.addView(updMsg);
        updater = new AppUpdater(this, sp, ui);
        AppUpdater.cleanup(this);

        // трафик идёт напрямую: пользователь должен это видеть всегда
        directWarn = Ui.text(this, "⚠ Всё напрямую: трафик не защищён, сайты видят ваш настоящий адрес", 13, Ui.TEXT, true);
        directWarn.setBackground(Ui.roundStroke(0xFF3A1D1D, Ui.RED, 12, this));
        directWarn.setPadding(dp(14), dp(10), dp(14), dp(10));
        directWarn.setVisibility(View.GONE);
        mainBox.addView(directWarn, lpMatch(12));

        // --- состояние
        stateCard = Ui.card(this);
        status = Ui.text(this, "", 13, Ui.MUTED, false);
        LinearLayout stateRow = new LinearLayout(this);
        stateRow.setGravity(Gravity.CENTER_VERTICAL);
        stateRow.addView(status, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        noExitHelp = Ui.help(this, "Выходов пока нет", "Ни одна известная нода не имеет права выхода (EXIT). Устройства могут быть связаны напрямую (P2P), "
                + "но в интернет через них выйти нельзя. Чтобы появился выход, вступите по приглашению ноды-выхода («Сеть и приглашения» → «Вступить»).\n\n"
                + "В режиме «VPN» туннель без выхода не передаёт трафик: защита от утечки (kill-switch) не ослабляется, поэтому трафик блокируется, а не идёт мимо VPN. "
                + "Если выход не нужен, переключитесь на «Сеть»: узел работает, VPN не включён.");
        noExitHelp.setVisibility(View.GONE);
        stateRow.addView(noExitHelp, Ui.helpParams(this));
        stateCard.addView(stateRow);
        mainBox.addView(stateCard, Ui.cardParams(this));

        // --- граф выходов
        LinearLayout graphCard = Ui.card(this);
        LinearLayout gh = Ui.titleWithHelp(this, "Выходы",
                "Граф сети: телефон в центре, ноды пронумерованы как в списке ниже. Нажмите на выход в списке или на графе, чтобы выбрать его; повторное нажатие возвращает автовыбор. "
                + "Удержание выхода открывает его настройки, удержание телефона — экран сети. «По пингу»: чем меньше пинг, тем ближе нода. "
                + "Линии показывают только известные участки пути и наблюдаемые связи, но не подтверждают доступность VPN. Подробности появляются при включённой отладке.");
        View sp1 = new View(this);
        gh.addView(sp1, new LinearLayout.LayoutParams(0, 1, 1f));
        android.widget.CheckBox pingBox = new android.widget.CheckBox(this);
        pingBox.setText("По пингу");
        pingBox.setTextSize(12);
        pingBox.setChecked(sp.getBoolean("ping_layout", false));
        gh.addView(pingBox);
        graphCard.addView(gh);
        topo = new TopologyView(this);
        topo.setOnPick((dest, name) -> toggleDefaultExit(dest, name));   // короткий тап: нода по умолчанию
        topo.setOnLongPick((dest, name) -> openNodeAdmin(dest, name, ""));   // удержание: настройки ноды
        topo.setOnPhonePick(() -> startActivity(new Intent(this, NetworkActivity.class)));
        graphCard.addView(topo, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(300)));
        nodeRows = new LinearLayout(this);
        nodeRows.setOrientation(LinearLayout.VERTICAL);
        graphCard.addView(nodeRows, lpMatch(8));
        exitsNote = Ui.text(this, "Нет нод с правом выхода. Вступите по приглашению.", 12, Ui.ORANGE, false);
        exitsNote.setVisibility(View.GONE);
        graphCard.addView(exitsNote, lpMatch(6));
        topo.setPingMode(pingBox.isChecked());
        pingBox.setOnCheckedChangeListener((v, on) -> { sp.edit().putBoolean("ping_layout", on).apply(); topo.setPingMode(on); });
        mainBox.addView(graphCard, Ui.cardParams(this));

        // --- маршрутизация
        LinearLayout routeCard = Ui.card(this);
        routeCard.addView(Ui.titleWithHelp(this, "Маршрутизация",
                "Что идёт через VPN, а что напрямую, и через какие выходы. Режимы: «Всё в туннель», «Всё напрямую», «Обход только заблокированного», «Всё РФ напрямую». "
                + "Изменения вступают в силу при следующем включении VPN."));
        routingSummary = Ui.muted(this, "");
        routingSummary.setPadding(0, dp(4), 0, dp(8));
        routeCard.addView(routingSummary);
        routeCard.addView(Ui.secondary(this, "Настроить", v -> startActivity(new Intent(this, RoutingActivity.class))));
        mainBox.addView(routeCard, Ui.cardParams(this));

        // --- сеть и приглашения: любая нода сама себе админ, поэтому карточка видна всегда
        adminBox = Ui.card(this);
        adminBox.addView(Ui.titleWithHelp(this, "Сеть и приглашения",
                "Выпускайте приглашения для серверов (первый запуск), пользователей и админов, знакомьте ноды друг с другом и правьте права. "
                + "«Вступить» — принять чужое приглашение (можно в несколько сетей, ничего не сбрасывается). Корня нет: управлять можно теми нодами, "
                + "которые признали вас админом (сервер при первом запуске по вашему приглашению). VPN для этого не обязателен, достаточно включить «Сеть»."));
        Button joinBtn = Ui.secondary(this, "Вступить", v -> startActivity(new Intent(this, JoinActivity.class)));
        joinBtn.setFilterTouchesWhenObscured(true);   // F8
        adminBox.addView(joinBtn, lpMatch(10));
        Button inviteBtn = Ui.primary(this, "Пригласить", v -> startActivity(new Intent(this, InviteIssueActivity.class)));
        inviteBtn.setFilterTouchesWhenObscured(true);   // F8
        adminBox.addView(inviteBtn, lpMatch(8));
        adminBox.addView(Ui.secondary(this, "Сеть: ноды, приглашения, права", v -> startActivity(new Intent(this, NetworkActivity.class))), lpMatch(8));
        mainBox.addView(adminBox, Ui.cardParams(this));
        mainBox.addView(updView, lpMatch(12));   // версия и результат проверки обновления: мелко внизу
        root.addView(mainBox);

        // --- сборка экрана: [кадр: подсказка, прокрутка, шторка журнала] + панель режимов
        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        outer.setBackgroundColor(Ui.BG);
        // закреплённая сверху строка: текущее состояние подключения (вместо названия приложения)
        topStatus = Ui.text(this, "", 17, Ui.TEXT, true);
        topStatus.setGravity(Gravity.CENTER);
        topStatus.setSingleLine(true);
        topStatus.setEllipsize(android.text.TextUtils.TruncateAt.END);
        topStatus.setBackground(Ui.roundStroke(Ui.CARD, Ui.STROKE, 0, this));
        topStatus.setPadding(dp(16), dp(12), dp(16), dp(12));
        topStatus.setVisibility(View.GONE);
        outer.addView(topStatus, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        FrameLayout frame = new FrameLayout(this);
        FrameLayout.LayoutParams hp = new FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.TOP);
        hp.topMargin = dp(8);
        frame.addView(pullHint, hp);
        frame.addView(sv, new FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        logConsole = new LogConsole(this, new LogConsole.Actions() {
            @Override public void ping() { diagPing(); }
            @Override public void speed() { diagSpeed(); }
            @Override public void ip() { diagIp(); }
            @Override public void debug(boolean on) { setDebugMode(on); }
            @Override public void share() { shareLog(); }
        });
        benchView = logConsole.speedOut();
        logConsole.setDebugUi(Util.debug);
        logConsole.setTranslationY(10000);
        frame.addView(logConsole, new FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT, Gravity.BOTTOM));
        frame.addOnLayoutChangeListener((v, l, t, r, bt, ol, ot, orr, ob) -> {
            FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) logConsole.getLayoutParams();
            int want = Math.max(dp(160), (bt - t) - dp(8));
            if (lp.height != want) { lp.height = want; logConsole.setLayoutParams(lp); }
            logConsole.post(logConsole::relayout);
        });
        outer.addView(frame, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        modePanel = buildModePanel();
        outer.addView(modePanel, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        setContentView(outer);
        // клавиатура (поле фильтра журнала): панель режимов прячется, журнал растёт сам вместе с кадром
        final View decor = getWindow().getDecorView();
        decor.getViewTreeObserver().addOnGlobalLayoutListener(() -> {
            android.graphics.Rect r = new android.graphics.Rect();
            decor.getWindowVisibleDisplayFrame(r);
            int full = decor.getRootView().getHeight();
            boolean kb = full > 0 && full - r.bottom > full * 0.15f;
            modePanel.setVisibility(kb && logConsole.isOpen() ? View.GONE : View.VISIBLE);
        });
        // Разрешение на уведомления просим один раз: повторный системный диалог при каждом запуске забирал фокус окна (на MIUI первое касание после
        // открытия терялось - одна из гипотез, см. ModeSlider).
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != 0 && !sp.getBoolean("notif_asked", false)) {
            sp.edit().putBoolean("notif_asked", true).apply();
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2);
        }
        // ключ ноды создаётся при запуске приложения (а не при включении «Сети»): вступление и выпуск работают сразу, при выключенной «Сети» тоже
        new Thread(() -> Ctl.call(this, Ctl.req("init")), "knothop-init").start();
        handleLink(getIntent());
        handleLabIntent(getIntent());
        // после показа экрана, в фоновом потоке: старт приложения от сети не зависит
        if (b == null && !Util.LAB_BUILD) ui.postDelayed(() -> checkUpdate(false), 2000);
    }

    @Override
    public void onBackPressed() {
        if (logConsole != null && logConsole.isOpen()) { logConsole.setOpen(false, true); return; }
        super.onBackPressed();
    }

    private void setDebugMode(boolean on) {
        sp.edit().putBoolean("debug", on).apply();
        Util.setDebug(on);
        logConsole.setDebugUi(on);
        Util.log(on ? "отладка включена: в журнал пишутся снимки состояния, причины обрывов, паузы процесса" : "отладка выключена");
    }

    @Override
    protected void onNewIntent(Intent in) {
        super.onNewIntent(in);
        setIntent(in);
        handleLink(in);
        handleLabIntent(in);
    }

    /**
     * Ссылка knothop://i/... (QR системной камеры, сообщение): принимается всегда, в том числе на первом запуске и на уже настроенном телефоне.
     * Показывается диалог с хешами нод, дальше вступление добавляется к уже принятым приглашениям. Пустая ссылка не принимается.
     */
    private void handleLink(Intent in) {
        if (in == null || !Intent.ACTION_VIEW.equals(in.getAction()) || in.getData() == null) return;
        String u = in.getData().toString();
        in.setData(null);
        if (!u.startsWith(Profile.LINK)) return;
        if (u.length() > MAX_PASTE) {
            android.widget.Toast.makeText(this, "Ссылка слишком длинная: такого приглашения не бывает", android.widget.Toast.LENGTH_LONG).show();
            return;
        }
        JoinFlow.confirmAndJoin(this, u, null);
    }

    @Override
    protected void onResume() {
        super.onResume();
        topo.setActive(true);
        String updRes = sp.getString("upd_result", "");
        if (!updRes.isEmpty()) { updView.setText(updRes); sp.edit().remove("upd_result").apply(); }
        updater.resume();
        Util.dbg("экран открыт");
        // режим, ради которого приложение было перезапущено (NodeLauncher): запись стирается до исполнения, цикла нет
        int pm = NodeLauncher.takePending(sp);
        if (pm != 0) applyMode(pm);
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
        if (p != null) JoinFlow.joinNow(this, p);
        String sel = in.getStringExtra("select");
        if (sel != null) select(sel);
        // H5: имитация сбоя нативной части при активном туннеле (процесс и VpnService живы, проверяется kill-switch)
        if (in.getBooleanExtra("native_fail", false)) {
            startService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_LAB_NATIVE_FAIL));
        }
        if (in.getBooleanExtra("stop", false)) {
            startService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_STOP));
        } else if (in.getBooleanExtra("auto", false) && VpnService.prepare(this) == null && !active() && !NodeLauncher.needsRestart()) {
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
        for (String k : new String[]{"profile", "select", "auto", "stop", "pub", "bench_mb", "routing", "routing_json", "download", "native_fail"}) in.removeExtra(k);
    }

    /** Первые 16 hex хеша, группами по 4 - для сверки глазами. */
    private static String fp(String h) { return JoinFlow.fp(h); }

    /**
     * Раз в 3 с вне главного потока: сколько пар вступления ещё ждут погашения (view.pending; при выключенной «Сети» - с диска). Нужно для
     * подсказки «включите Сеть». Согласия на управление телефоном больше нет: вступление никому его не даёт (ADR 0028 §2.4).
     */
    private void pollPending() {
        if (System.currentTimeMillis() - pendPollAt < 3000) return;
        pendPollAt = System.currentTimeMillis();
        new Thread(() -> {
            JSONObject v = Ctl.call(this, Ctl.req("view"));
            JSONObject pend = v.optJSONObject("pending");
            JSONArray pairs = pend == null ? null : pend.optJSONArray("pairs");
            int w = 0;
            for (int i = 0; pairs != null && i < pairs.length(); i++) if ("waiting".equals(pairs.optJSONObject(i).optString("state"))) w++;
            pendWaiting = w;
            pendTotal = pairs == null ? 0 : pairs.length();
        }, "knothop-pending").start();
    }

    private boolean active() { return JoinFlow.nodeActive(); }

    private AlertDialog nameDialog;

    /**
     * Имя телефона для сети (state/node-name.txt, его нативная часть сообщает выходам в T_USE). Спрашиваем один раз, пока имя - автоимя
     * «телефон-XXXXXX» (по хешу ключа) или не задано; позже имя меняется в настройках своей ноды.
     */
    private void maybeAskName() {
        if (sp.getBoolean("name_asked", false) || (nameDialog != null && nameDialog.isShowing())) return;
        if (!NodeName.isAuto(getFilesDir())) { sp.edit().putBoolean("name_asked", true).apply(); return; }
        nameDialog = NodeName.dialog(this, getFilesDir(), () -> sp.edit().putBoolean("name_asked", true).apply());
    }

    private static final String[] MODE_TITLE = {"Отключено", "В сети нод, без VPN", "VPN включён"};

    /** Закреплённая внизу панель: анимированный переключатель с тремя точками притяжения (слева - отключено, середина - сеть нод без VPN, справа - VPN). */
    private LinearLayout buildModePanel() {
        LinearLayout p = new LinearLayout(this);
        p.setOrientation(LinearLayout.VERTICAL);
        p.setBackground(Ui.roundStroke(Ui.CARD, Ui.STROKE, 0, this));
        p.setPadding(dp(20), dp(12), dp(20), dp(10));
        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.HORIZONTAL);
        top.setGravity(Gravity.CENTER);
        modeText = Ui.text(this, "", 15, Ui.TEXT, true);
        modeText.setGravity(Gravity.CENTER);
        top.addView(modeText);
        top.addView(Ui.help(this, "Режимы", "Отключено — узел остановлен. Сеть — телефон работает как узел сети нод (приглашения, права, список нод), но трафик через VPN не идёт. "
                + "VPN — весь трафик по правилам маршрутизации идёт через выход. Переключатель можно тянуть или просто тапнуть по нужной точке."), Ui.helpParams(this));
        p.addView(top);
        modeSlider = new ModeSlider(this);
        modeSlider.setListener(m -> applyMode(m));
        modeSlider.setContentDescription("Режим работы");   // для чтения с экрана и deploy/phones.sh
        p.addView(modeSlider, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
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
        if (modeSlider == null || modeSlider.isDragging()) return;
        int m = curMode();
        if (modeSlider.mode() != m) modeSlider.setMode(m, true);
        String t = MODE_TITLE[m];
        int col = ModeSlider.COLORS[m];
        if (KnotHopVpnService.tunHeld) { t = "VPN не работает, трафик заблокирован"; col = Ui.RED; }
        else if (!KnotHopVpnService.lastError.isEmpty() && m != 0 && "error".equals(KnotHopVpnService.phase)) t += " · сбой";
        modeText.setText(t);
        modeText.setTextColor(col);
    }

    private void applyMode(int m) {
        int cur = curMode();
        if (m == cur) return;
        if (KnotHopVpnService.tunHeld && m != 0) {
            android.widget.Toast.makeText(this, "Сначала переведите переключатель в «Откл.», затем включите заново", android.widget.Toast.LENGTH_LONG).show();
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
        // единые ворота: в «грязном» процессе (узел уже запускался) перезапускает приложение и продолжает после перезапуска
        if (!NodeLauncher.start(this, m)) {
            pendingMode = -1;
            android.widget.Toast.makeText(this, "Не удалось перезапустить приложение. Закройте его и откройте снова", android.widget.Toast.LENGTH_LONG).show();
        }
    }

    private TextView geoMsg;
    private volatile boolean geoBusy;
    /** Единичный анонс по просьбе пользователя не чаще раза в 30 с; штатный период анонса узла (600 с) не меняется. */
    private static final long ANNOUNCE_MIN_MS = 30_000;
    private long lastManualAnnounce;

    /**
     * Потяни-чтобы-обновить: проверка версии приложения (диалог, если есть новая), обновление геоданных, права и список нод,
     * единичный анонс себя и проверка связи со всеми нодами. Опрос нод и анонс требуют включённого режима «Сеть» или «VPN»:
     * узел работает только в них.
     */
    private void pullRefresh() {
        checkUpdate(true);
        refreshGeo();
        if (!active()) {
            android.widget.Toast.makeText(this, "Версия и геоданные проверяются. Чтобы обновить ноды, включите «Сеть» или «VPN»", android.widget.Toast.LENGTH_SHORT).show();
            return;
        }
        refreshNodes();
        long now = android.os.SystemClock.elapsedRealtime();
        if (lastManualAnnounce == 0 || now - lastManualAnnounce >= ANNOUNCE_MIN_MS) {
            lastManualAnnounce = now;
            Native.kick(0);
        }
        Native.kick(1);
    }

    // ---------------------------------------------------------------- диагностика (кнопки в шторке журнала)

    private void diagOut(String t) {
        ui.post(() -> { if (!isFinishing() && !isDestroyed()) logConsole.setDiag(t); });
    }

    /** Пинг: TCP-рукопожатия до адреса диагностики (DiagTarget, всегда в туннеле) через сеть нашего VPN (ICMP из приложения недоступен) и RTT до текущего выхода. */
    private void diagPing() {
        final KnotHopVpnService.SpeedPath path = KnotHopVpnService.speedPath();
        if (path == null) {
            logConsole.setDiag(KnotHopVpnService.allDirectActive()
                    ? "Пинг: пресет «Всё напрямую», туннеля нет, проверять нечего"
                    : "VPN не подключён к выходу" + (KnotHopVpnService.speedWhy.isEmpty() ? "" : " (" + KnotHopVpnService.speedWhy + ")"));
            return;
        }
        String exitRtt = "";
        JSONObject j = currentStatus();
        try {
            JSONObject cur = j == null ? null : j.optJSONObject("current");
            JSONArray exs = j == null ? null : j.optJSONArray("exits");
            for (int i = 0; cur != null && exs != null && i < exs.length(); i++) {
                JSONObject e = exs.optJSONObject(i);
                if (e != null && cur.optString("d").equals(e.optString("d")) && !e.isNull("r"))
                    exitRtt = "до выхода " + TopologyView.shortName(cur.optString("n")) + ": " + Math.round(e.optDouble("r")) + " мс";
            }
        } catch (Throwable ignored) { }
        final String exitPart = exitRtt;
        logConsole.pingBtn.setEnabled(false);
        logConsole.setDiag("Пинг…");
        new Thread(() -> {
            String res;
            try {
                java.net.InetAddress target = java.net.InetAddress.getByName(DiagTarget.HOST);
                // адрес диагностики всегда в туннеле (маршрут /32, вырезка из «мимо VPN»); иначе это ошибка маршрутов, а не результат
                if (path.bypasses(target)) throw new java.io.IOException("адрес диагностики оказался вне туннеля (ошибка маршрутов)");
                long best = Long.MAX_VALUE, sum = 0;
                int ok = 0;
                for (int i = 0; i < 4 && path.valid(); i++) {
                    long t0 = System.nanoTime();
                    try (java.net.Socket s = path.network.getSocketFactory().createSocket()) {
                        s.connect(new java.net.InetSocketAddress(target, 443), 4000);
                        long ms = (System.nanoTime() - t0) / 1_000_000;
                        best = Math.min(best, ms); sum += ms; ok++;
                    } catch (java.io.IOException ignored) { }
                }
                res = ok == 0 ? DiagTarget.HOST + " через туннель: нет ответа (выход не отвечает или недоступен)"
                        : DiagTarget.HOST + " через туннель: " + best + " мс (среднее " + sum / ok + ", ответов " + ok + " из 4)";
            } catch (Throwable e) {
                res = "Пинг не выполнен: " + e.getMessage();
            }
            final String out = exitPart.isEmpty() ? res : res + "\n" + exitPart;
            Util.log("пинг: " + out);
            ui.post(() -> { if (!isFinishing() && !isDestroyed()) { logConsole.setDiag(out); logConsole.pingBtn.setEnabled(true); } });
        }, "knothop-diag-ping").start();
    }

    private void diagSpeed() {
        if (!"up".equals(KnotHopVpnService.phase)) {
            logConsole.setDiag("Скорость: включите режим «VPN» и дождитесь выхода");
            return;
        }
        if (sp.getBoolean("speed_ack", false) && KnotHopVpnService.speedPath() != null) requestBench(25);
        else confirmBench();
    }

    /**
     * Внешний IP и страна: Cloudflare trace по IP (без DNS) строго через сеть нашего VPN; адрес диагностики всегда в туннеле при любых правилах.
     * «Всё напрямую» и режим без TUN: туннеля нет, запрос идёт напрямую и результат так и помечен. Адрес показывается только на экране, в журнал и logcat не пишется.
     */
    private void diagIp() {
        final KnotHopVpnService.SpeedPath path = KnotHopVpnService.speedPath();
        final boolean allDirect = KnotHopVpnService.allDirectActive();
        logConsole.ipBtn.setEnabled(false);
        logConsole.setDiag("Запрашиваю IP…");
        new Thread(() -> {
            String res;
            try {
                java.net.URL url = new java.net.URL(DiagTarget.URL);
                boolean tunnel = path != null;
                if (tunnel && path.bypasses(java.net.InetAddress.getByName(DiagTarget.HOST)))
                    throw new java.io.IOException("адрес диагностики оказался вне туннеля (ошибка маршрутов)");
                java.net.HttpURLConnection c = (java.net.HttpURLConnection) (tunnel ? path.network.openConnection(url) : url.openConnection());
                c.setConnectTimeout(8000);
                c.setReadTimeout(8000);
                if (c.getResponseCode() != 200) throw new java.io.IOException("HTTP " + c.getResponseCode());
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                try (java.io.InputStream in = c.getInputStream()) {
                    byte[] buf = new byte[2048];
                    int n;
                    while ((n = in.read(buf)) > 0 && bo.size() < 16384) bo.write(buf, 0, n);
                }
                String[] t = DiagTarget.parseTrace(bo.toString("UTF-8"));
                if (t[0].isEmpty()) throw new java.io.IOException("в ответе нет адреса");
                res = "IP: " + t[0] + (t[1].isEmpty() ? "" : "\n" + DiagTarget.country(t[1]))
                        + "\n" + (tunnel ? "запрос прошёл через туннель"
                        : allDirect ? "туннеля нет (пресет «Всё напрямую»): это ваш прямой адрес, не VPN"
                        : "VPN не подключён к выходу: это ваш прямой адрес, не VPN");
            } catch (Throwable e) {
                res = "IP не получен: " + e.getMessage() + (path == null ? (allDirect ? "\n(туннеля нет: «Всё напрямую»)" : "\n(VPN не подключён к выходу)") : "");
            }
            final String out = res;
            Util.log("проверка IP выполнена");   // адрес в журнал не пишем
            ui.post(() -> { if (!isFinishing() && !isDestroyed()) { logConsole.setDiag(out); logConsole.ipBtn.setEnabled(true); } });
        }, "knothop-diag-ip").start();
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

    private static final long UPDATE_EVERY_MS = 24L * 3600 * 1000;

    private void updShow(String t) {
        updMsg.setText(t);
        if (updView != null) updView.setText(t);
    }

    /**
     * Свежий релиз на GitHub. Автоматически (при открытии, не чаще раза в сутки): только строка «Доступна версия X» под кнопкой, без диалога
     * и без скачивания. Вручную (кнопка, потяни-чтобы-обновить): ответ всегда, при новой версии - диалог с загрузкой через {@link AppUpdater}.
     */
    private void checkUpdate(final boolean manual) {
        if (isFinishing() || isDestroyed()) return;
        long now = System.currentTimeMillis();
        if (!manual && now - sp.getLong("upd_ts", 0) < UPDATE_EVERY_MS) return;
        if (manual) updShow("Проверяю…");
        final long have = installedCode();
        UpdateCheck.run(r -> ui.post(() -> {
            if (isFinishing() || isDestroyed()) return;
            if (r.error != null) {
                if (manual) updShow("Не удалось проверить обновление: " + r.error);
                return;
            }
            sp.edit().putLong("upd_ts", System.currentTimeMillis()).apply();
            if (r.latest <= have) {
                if (manual) updShow("Установлена последняя версия " + installedName() + " (" + have + ")");
                return;
            }
            updShow("Доступна версия " + r.tag + " (у вас " + installedName() + ", " + have + ")");
            if (!manual) return;
            new AlertDialog.Builder(this).setTitle("Доступно обновление")
                .setMessage("Вышла версия " + r.tag + ", у вас " + installedName() + ".\nПриложение скачает файл с GitHub, проверит контрольную сумму и подпись и предложит установить. "
                    + "Установка перезапустит приложение: VPN прервётся, включите его заново.")
                .setPositiveButton("Скачать", (d, w) -> updater.start(r.tag))
                .setNegativeButton("Позже", null)
                .show();
        }));
    }

    private final Runnable tick = new Runnable() {
        public void run() {
            refresh();
            pollPending();
            if (!Util.LAB_BUILD) maybeAskName();
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
        // главный экран всегда; состояния «настроен/профиль» нет. Подсказка про вступление - из ожидающих пар ядра.
        if (pendWaiting > 0 && !active()) {
            showHeader("Приглашение принято к исполнению (ждут нод: " + pendWaiting + "). Включите «Сеть» или «VPN» внизу: телефон свяжется с нодами и погасит пары", true);
        } else if (pendWaiting > 0) {
            showHeader("Погашаю приглашение: ждут ответа нод " + pendWaiting + " из " + pendTotal, false);
        } else {
            header.setVisibility(View.GONE);
        }
        updateModePanel();
        // Верх экрана: что происходит сейчас, активное соединение, скорость. Остальное - в журнал (консоль внизу).
        String phase = KnotHopVpnService.phase;
        logChange("состояние", phase);
        String doing = null, conn = null, speed = null;
        // настоящий сбой (служба в ошибке или не удалось включить TUN); отсутствие выходов и нод сбоем не считается
        if (!KnotHopVpnService.lastError.isEmpty() && ("error".equals(phase) || KnotHopVpnService.tunHeld || KnotHopVpnService.mode == 1)) doing = "Сбой: " + KnotHopVpnService.lastError;
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
                JSONArray exAll = j.optJSONArray("exits");
                nodeCount = exAll == null ? 0 : exAll.length();
                if (nodeCount > 0) noExitsSince = 0; else if (noExitsSince == 0) noExitsSince = System.currentTimeMillis();
                P2p.Summary ps = P2p.summary(j.optJSONArray("p2p"));
                p2pConnected = ps.connected; p2pTotal = ps.total; p2pFailed = ps.failed;
                exitName = cur == null ? "" : TopologyView.shortName(cur.optString("n"));
                if (cur != null) {
                    StringBuilder c = new StringBuilder("выход: ").append(TopologyView.shortName(cur.optString("n")));
                    if (pinned.equalsIgnoreCase(cur.optString("d"))) c.append("  ★");
                    if (!cur.isNull("via")) {
                        String vd = cur.optString("via"); String vn = vd;
                        JSONArray exs = j.optJSONArray("exits");
                        for (int q = 0; exs != null && q < exs.length(); q++) if (vd.equals(exs.optJSONObject(q).optString("d"))) vn = TopologyView.shortName(exs.optJSONObject(q).optString("n"));
                        c.append("  через ").append(vn);
                    }
                    if (Util.debug) c.append("  · ").append(TopologyView.carrierName(cur.optString("carrier")));
                    conn = c.toString();
                    logChange("соединение", conn + " (носитель - открытый сокет, не путь RNS)");
                } else if (doing == null) {
                    doing = curMode() == 1 ? "Узел работает в сети. Выходы для VPN появятся, когда нода ответит" : "Ищу выход…";
                }
                // выходов нет вовсе (только P2P-контакты или пустая таблица): выбора нет, «восстанавливаю путь к выбранной ноде» неверно
                if (cur == null && noExits() && (doing == null || !doing.startsWith("Сбой"))) {
                    doing = "Выходов пока нет" + (p2pTotal > 0 ? "\nP2P: связь с " + p2pConnected + " из " + p2pTotal + " устройств" : "");
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
                topo.update(j);
                JSONArray lt = j.optJSONArray("log_tail");
                if (lt != null) for (int q = lt.length() - 1; q >= 0; q--) { String ln = lt.optString(q); if (logSeen.add(ln)) Util.lab("NLOG " + ln); }
                buildList(j);
            } catch (Throwable e) {
                doing = "статус: " + e;
            }
        } else {
            nodeCount = 0; p2pConnected = 0; p2pTotal = 0; p2pFailed = 0;
            noExitsSince = 0;
            exitName = "";
            prevTs = 0;
            rUp = rDown = 0;
            try { topo.update(new JSONObject("{\"state\":\"idle\",\"ip\":\"\"}")); } catch (Exception ignored) { }
            nodeRows.removeAllViews();
            nodeRowsKey = "";
            updateBenchUi(state, null, null);
            if (doing == null) doing = "idle".equals(phase) ? "" : "Запускаюсь…";
        }
        StringBuilder s = new StringBuilder();
        if (doing != null) s.append(doing).append('\n');
        if (conn != null) s.append(conn).append('\n');
        if (speed != null) s.append(speed).append('\n');
        if (s.length() > 0) s.setLength(s.length() - 1);
        status.setText(s);
        status.setVisibility(s.length() == 0 ? View.GONE : View.VISIBLE);
        boolean noEx = noExits();
        noExitHelp.setVisibility(noEx ? View.VISIBLE : View.GONE);
        exitsNote.setVisibility(noEx && active() ? View.VISIBLE : View.GONE);
        stateCard.setVisibility(s.length() == 0 ? View.GONE : View.VISIBLE);
        showState(doing != null && doing.startsWith("Сбой") ? doing : null);
        Util.lab("STATUS " + s.toString().replace("\n", " | "));
        String log = Util.read(new File(state, "log.txt"));
        String[] lines = Util.mergedLog(log);
        logConsole.setLines(lines);
        if (lines.length > 0) Util.lab("LOG " + lines[lines.length - 1]);
    }

    /** Нет нод с правом выхода уже ≥10 с по свежему статусу (при запуске таблица выходов появляется не сразу). */
    private boolean noExits() {
        return noExitsSince != 0 && System.currentTimeMillis() - noExitsSince >= 10_000;
    }

    private static String nodesWord(int n) {
        int a = n % 100, b = n % 10;
        return a >= 11 && a <= 14 ? "нод" : b == 1 ? "нода" : b >= 2 && b <= 4 ? "ноды" : "нод";
    }

    /**
     * Закреплённая сверху строка состояния (цвет по режиму), предупреждение «всё напрямую» и краткая сводка маршрутизации.
     * @param failure текст сбоя («Сбой: …») или null
     */
    private void showState(String failure) {
        int m = curMode();
        boolean held = KnotHopVpnService.tunHeld;
        String t;
        int col;
        if (held) { t = "Сбой: VPN не работает, трафик заблокирован"; col = Ui.RED; }
        else if (failure != null) {
            String why = failure.startsWith("Сбой: ") ? failure.substring(6) : failure;
            t = "Сбой: " + (why.length() > 40 ? why.substring(0, 40) + "…" : why);
            col = Ui.RED;
        } else if (m == 0) { t = "Отключено"; col = Ui.MUTED; }
        else if (m == 1) {
            if (nodeCount > 0) { t = "Сеть: " + nodeCount + " " + nodesWord(nodeCount); col = ModeSlider.COLORS[1]; }
            else if (p2pTotal > 0) { t = "Сеть: P2P " + p2pConnected + " из " + p2pTotal + (p2pFailed > 0 ? " · не удалось: " + p2pFailed : ""); col = ModeSlider.COLORS[1]; }
            else { t = "Сеть: подключаюсь…"; col = ModeSlider.COLORS[1]; }
        } else if (!exitName.isEmpty() && "up".equals(KnotHopVpnService.phase)) { t = "VPN: " + exitName; col = ModeSlider.COLORS[2]; }
        else if (noExits()) { t = "VPN: выходов нет, трафик не идёт"; col = ModeSlider.COLORS[1]; }
        else { t = "VPN: подключаюсь…"; col = ModeSlider.COLORS[1]; }
        topStatus.setText(t);
        topStatus.setTextColor(col);
        RoutingCfg rc = RoutingCfg.load(new File(getFilesDir(), "state"));
        routingSummary.setText(RoutingPresets.title(rc) + (rc.exitFilterSummary().isEmpty() ? "" : " · " + rc.exitFilterSummary()));
        directWarn.setVisibility(m == 2 && RoutingPresets.ALL_DIRECT.equals(rc.preset()) ? View.VISIBLE : View.GONE);
    }

    private void confirmBench() {
        if (KnotHopVpnService.speedPath() == null) {
            new AlertDialog.Builder(this).setMessage("Тест требует включённый режим «VPN» (переключатель справа) и готовый выход. Сокеты теста идут только через туннель." + (KnotHopVpnService.speedWhy.isEmpty() ? "" : "\n\nПричина: " + KnotHopVpnService.speedWhy)).setPositiveButton("OK", null).show();
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
        if (logConsole == null) return;
        logConsole.speedBtn.setEnabled(!SpeedTest.running());
        if (SpeedTest.running() || !SpeedTest.text.startsWith("Тест доступен")) benchView.setText(SpeedTest.text);
    }

    private final java.util.Set<String> logSeen = new java.util.HashSet<>();

    /** Нумерованный список повторяет порядок графа и остаётся читаемым при тесном расположении узлов. */
    private void buildList(JSONObject j) {
        JSONArray ex = j.optJSONArray("exits");
        if (ex != null) RoutingCfg.cacheNodes(getFilesDir(), ex);
        JSONArray p2p = j.optJSONArray("p2p");
        String selected = j.optString("selected", "");
        JSONObject cur = j.optJSONObject("current");
        String activeDest = cur == null ? "" : cur.optString("d", "");
        java.util.List<String> labels = new java.util.ArrayList<>();
        java.util.List<String> dests = new java.util.ArrayList<>();
        java.util.List<String> names = new java.util.ArrayList<>();
        for (int i = 0; ex != null && i < ex.length(); i++) {
            JSONObject e = ex.optJSONObject(i);
            if (e == null) continue;
            String dest = e.optString("d", ""), name = TopologyView.shortName(e.optString("n", "?"));
            String presence = e.optString("presence", "unknown");
            String state = dest.equals(activeDest) ? "связь установлена"
                : "dead".equals(presence) ? "не отвечает, соседи не видели (выберите, чтобы проверить снова)"
                : "seen".equals(presence) && !e.isNull("seen_s") ? "сосед видел " + Util.agoText(e.optLong("seen_s")) + " назад"
                : "reported".equals(presence) ? "жив по данным соседей"
                : "fail".equals(e.optString("lk")) ? "нет связи" : "доступность неизвестна";
            String detail = "";
            if (Util.debug) {
                String vis = e.optString("vis", "none"), carrier = TopologyView.carrierName(e.optString("c", "none"));
                detail = "\nПуть RNS: " + ("direct".equals(vis) ? "прямой" : "via".equals(vis) ? "через транзит" : "нет данных") + " · носитель " + carrier;
                JSONObject quic = dest.equals(activeDest) && cur != null ? cur.optJSONObject("quic") : null;
                boolean meshPath = quic != null && "mesh".equals(quic.optString("kind"));
                if (meshPath) detail += " · транзит mesh: число прыжков неизвестно";
                else if (!e.isNull("h")) detail += " · промежуточных нод RNS: " + TopologyView.intermediateHops(e.optInt("h", 0));
                if (!e.isNull("r") && e.optDouble("r", -1) > 0) detail += " · RTT " + Math.round(e.optDouble("r")) + " мс";
                if (!e.isNull("why") && !e.optString("why").isEmpty()) detail += "\n" + TopologyView.whyText(e.optString("why"));
            }
            labels.add((labels.size() + 1) + ". " + name + (dest.equalsIgnoreCase(selected) ? " ★" : "") + " — " + state + detail);
            dests.add(dest); names.add(name);
        }
        for (int i = 0; p2p != null && i < p2p.length(); i++) {
            JSONObject e = p2p.optJSONObject(i);
            if (e == null) continue;
            String name = P2p.name(e), state = e.optString("state", "trying");
            String simple = P2p.connected(state) ? "связь установлена" : P2p.failed(e) ? "нет связи" : "подключается";
            labels.add((labels.size() + 1) + ". Устройство " + name + " — " + simple + (Util.debug ? "\n" + P2p.text(e) : ""));
            dests.add(""); names.add(name);
        }
        String key = labels.toString() + dests.toString();
        if (key.equals(nodeRowsKey)) return;
        nodeRowsKey = key;
        nodeRows.removeAllViews();
        for (int i = 0; i < labels.size(); i++) {
            final String dest = dests.get(i), name = names.get(i);
            Button row = Ui.secondary(this, labels.get(i), v -> {
                if (dest.isEmpty()) startActivity(new Intent(this, NetworkActivity.class));
                else toggleDefaultExit(dest, name);
            });
            if (!dest.isEmpty()) row.setOnLongClickListener(v -> { openNodeAdmin(dest, name, ""); return true; });
            nodeRows.addView(row, lpMatch(4));
        }
    }

    private boolean usersBusy;

    private java.util.Map<String, String> knownNames() {
        java.util.Map<String, String> m = new java.util.HashMap<>();
        JSONObject j = currentStatus();
        JSONArray ex = j == null ? null : j.optJSONArray("exits");
        for (int i = 0; ex != null && i < ex.length(); i++) {
            JSONObject e = ex.optJSONObject(i);
            String id = e == null ? "" : e.optString("id", "").toLowerCase(java.util.Locale.ROOT);
            if (id.matches("[0-9a-f]{32}")) m.put(id, Rights.clip(TopologyView.shortName(e.optString("n", "?"))));
        }
        return m;
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
                .putExtra(NodeSettingsActivity.EXTRA_TARGET, dest)
                .putExtra(NodeSettingsActivity.EXTRA_NAME, name == null ? "Нода" : name)
                .putExtra(NodeSettingsActivity.EXTRA_FINGERPRINT, fp);
        startActivity(in);
    }
}
