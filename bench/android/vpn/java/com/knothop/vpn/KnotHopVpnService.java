package com.knothop.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.IpPrefix;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.FileObserver;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;

import org.json.JSONObject;

import java.io.File;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * VPN-сервис: поднимает TUN с адресом из профиля, отдаёт дескриптор нативной части (knothopd client) и следит за ней.
 * Процесс привязан к физической сети до создания TUN: TCP/QUIC-носители не уходят в свой VPN.
 * Сокеты теста скорости явно привязаны к VPN Network (включая DNS), без fallback.
 * Сервера и ключи берутся только из профиля (после спаривания), ничего не запрашивается по сети до подключения.
 */
public class KnotHopVpnService extends VpnService {
    static final String A_START = "com.knothop.vpn.START";
    static final String A_STOP = "com.knothop.vpn.STOP";
    /** Только лабораторная сборка (см. labNativeFail): имитация сбоя нативной части. */
    static final String A_LAB_NATIVE_FAIL = "com.knothop.vpn.LAB_NATIVE_FAIL";
    /** Выбрать режим (EXTRA_MODE): 0 - отключено, 1 - в сети нод без VPN, 2 - VPN. Узел при переключении 1/2 не перезапускается. */
    static final String A_MODE = "com.knothop.vpn.MODE";
    static final String EXTRA_MODE = "mode";
    static final String EXTRA_ARGS = "args";
    private static final String CHANNEL = "knothop";

    /** Выбранный режим (0 - сервис не работает). */
    static volatile int mode = 0;
    /** Подключение и снятие TUN идут строго по очереди. */
    private final Object modeLock = new Object();
    private String tunIp = "";

    /** idle | tun | connecting | up | stopping | error */
    static volatile String phase = "idle";
    static volatile String lastError = "";
    static volatile long startedMs = 0;
    /** H5: после сбоя TUN оставлен открытым без чтения (трафик отбрасывается, мимо VPN не уходит). Выход - только «Отключить». */
    static volatile boolean tunHeld = false;
    private ParcelFileDescriptor tun;
    private Thread worker;
    private File state;
    private String extraArgs = "";
    private ConnectivityManager cm;
    private ConnectivityManager.NetworkCallback netCb;
    private Network carrierNetwork;
    private int excludedRouteCount;
    private static volatile KnotHopVpnService live;
    private final Handler serviceUi = new Handler(Looper.getMainLooper());
    private FileObserver serviceObserver;
    private Object watchSession;
    private String serviceKey = "";

    @Override
    public synchronized int onStartCommand(Intent intent, int flags, int startId) {
        String a = intent == null ? null : intent.getAction();
        if (A_STOP.equals(a)) {
            stopVpn();
            return START_NOT_STICKY;
        }
        if (Util.LAB_BUILD && A_LAB_NATIVE_FAIL.equals(a)) {
            labNativeFail();
            return START_NOT_STICKY;
        }
        int want = A_MODE.equals(a) ? intent.getIntExtra(EXTRA_MODE, 2) : 2;
        if (want == 0) {
            stopVpn();
            return START_NOT_STICKY;
        }
        if (want != 1) want = 2;
        if ("stopping".equals(phase)) {
            foreground("останавливаю");   // startForegroundService обязывает вызвать startForeground даже для отклонённой просьбы
            return START_NOT_STICKY;
        }
        if (worker != null && worker.isAlive()) {
            foreground(statusText());
            if (!"error".equals(phase)) switchMode(want);
            return START_NOT_STICKY;
        }
        if (tun != null) cleanup();   // TUN, оставленный после сбоя (tunHeld), заменяем новым
        mode = want;
        extraArgs = intent != null && intent.getStringExtra(EXTRA_ARGS) != null ? intent.getStringExtra(EXTRA_ARGS) : "";
        foreground("подключаюсь");
        state = new File(getFilesDir(), "state");
        state.mkdirs();
        // Only known transient publications. Never infer that an unfamiliar file is disposable:
        // identity, Trust, HOST_ACCESS, journals, pins and future enrollment state must survive APK updates.
        for (String name : new String[]{"fin", "status.json", "service.json", "whoami.json", "error.txt", "log.txt"})
            new File(state, name).delete();
        lastError = "";
        phase = "connecting";
        startedMs = System.currentTimeMillis();
        final Object session = new Object();
        watchSession = session;
        worker = new Thread(() -> run(session), "knothop-vpn");
        worker.start();
        return START_NOT_STICKY;
    }

    private void foreground(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, "KnotHop", NotificationManager.IMPORTANCE_LOW));
        Intent stop = new Intent(this, KnotHopVpnService.class).setAction(A_STOP);
        PendingIntent pi = PendingIntent.getService(this, 1, stop, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent open = PendingIntent.getActivity(this, 2, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, CHANNEL).setContentTitle("KnotHop").setContentText(text)
                .setSmallIcon(android.R.drawable.ic_lock_lock).setOngoing(true).setContentIntent(open)
                .addAction(new Notification.Action.Builder(null, "Отключить", pi).build()).build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        else startForeground(1, n);
    }

    private void run(Object session) {
        Util.svc("service run() start");
        try {
            migrateLegacyRoutingBeforeNative();
            RoutingCfg.ensureDefaults(state);
            Profile prof = Profile.parse(getSharedPreferences("p", MODE_PRIVATE).getString("profile", ""));
            File pf = new File(state, "profile.txt");
            Files.write(pf.toPath(), prof.raw.getBytes(StandardCharsets.UTF_8));
            pf.setReadable(false, false);
            pf.setReadable(true, true);
            String tunIp;
            String clientArgs;
                // 0013: ключ клиента создаёт нативная часть сама (identity.key в state), адрес в туннеле выводится из него
                if (Native.runVpn("whoami --state " + state.getAbsolutePath(), state.getAbsolutePath()) != 0) {
                    throw new IllegalStateException("не удалось создать ключ: " + Util.read(new File(state, "error.txt")));
                }
                tunIp = new JSONObject(Util.read(new File(state, "whoami.json"))).getString("ip");
                File pub = new File(state, "public_rns.txt");
                // лаборатория: подмена списка публичных узлов (хаб в LAN), чтобы стенд не нагружал настоящую публичную RNS
                String labPub = Util.LAB_BUILD ? getSharedPreferences("p", MODE_PRIVATE).getString("lab_pub", "") : "";
                Files.write(pub.toPath(), (labPub.isEmpty() ? Util.PUBLIC_RNS : labPub + "\n").getBytes(StandardCharsets.UTF_8));
                clientArgs = "--invite-file " + pf.getAbsolutePath() + " --public-rns-file " + pub.getAbsolutePath();

            synchronized (this) {
                if (watchSession != session) return;
                bindCarrierBeforeTun();
                phase = "tun";
            }
            this.tunIp = tunIp;
            synchronized (modeLock) {
                // Узел всегда стартует без TUN (--tun-fd -2), дескриптор ему передаётся через почтовый ящик: так же, как при переключении режимов.
                if (mode == 2 && tun == null) establishTun();
                if (tun != null) Native.setTun(tun.getFd());
                else Native.setTun(-1);
            }

            synchronized (this) {
                if (watchSession != session) return;
                registerNetworkWatcher(session);
                phase = "connecting";
                serviceUi.post(() -> startServiceWatcher(session));
            }
            Util.svc("phase connecting, mode " + mode);
            String args = "client --state " + state.getAbsolutePath() + " " + clientArgs
                    + " --tun-fd -2 --fail-ms 3000 --workers 4 " + extraArgs;
            if (Util.LAB_BUILD) {
                try {
                    // Частные адреса разрешены только в явно настроенной изолированной лаборатории, не при диагностике пилота.
                    boolean localLab = !getSharedPreferences("p", MODE_PRIVATE).getString("lab_pub", "").isEmpty();
                    if (localLab) android.system.Os.setenv("KNOTHOP_ALLOW_PRIVATE_DIAL", "1", true);
                    else android.system.Os.unsetenv("KNOTHOP_ALLOW_PRIVATE_DIAL");
                    android.system.Os.setenv("KNOTHOP_DEBUG", "1", true);
                } catch (Exception ignored) { }
            }
            Native.setDebug(Util.debug);
            int rc = Native.runVpn(args, state.getAbsolutePath());
            if (!"stopping".equals(phase)) {
                String err = Util.read(new File(state, "error.txt"));
                Util.svc("native exited rc=" + rc + " err=" + err);
                fail(err.isEmpty() ? "нативная часть завершилась (rc=" + rc + ")" : err, session);
            }
        } catch (Throwable t) {
            fail(t.toString(), session);
        }
    }

    /**
     * Создаёт TUN с адресом клиента. Раздельное туннелирование: подсети правил «мимо VPN» исключаются из туннеля (Android 13+). Нативная
     * часть собирает их из списков (самые крупные блоки первыми, не больше предела Binder). Если система отказывает, берём вдвое меньше,
     * затем без исключений. Вызывать под modeLock.
     */
    private void establishTun() throws Exception {
        List<String> direct = directRoutes();
        int excluded = Build.VERSION.SDK_INT >= 33 ? direct.size() : 0;
        ParcelFileDescriptor made;
        while (true) {
            try {
                Builder b;
                excluded = addExcluded(b = newBuilder(tunIp), direct, excluded);
                made = b.establish();
                break;
            } catch (Throwable t) {
                if (excluded == 0) throw t;
                Util.svc("establish with " + excluded + " excluded failed: " + t);
                excluded = excluded > 200 ? excluded / 2 : 0;
            }
        }
        if (made == null) throw new IllegalStateException("система не выдала TUN (разрешение VPN отозвано?)");
        tun = made;
        excludedRouteCount = excluded;
        getSharedPreferences("p", MODE_PRIVATE).edit().putString("routing_sig", RoutingCfg.load(state).directSig()).apply();
        Util.svc("excluded routes: " + excluded + " of " + direct.size() + ", tun fd " + made.getFd());
        try { if (carrierNetwork != null) setUnderlyingNetworks(new Network[]{carrierNetwork}); } catch (Throwable ignored) { }
    }

    /**
     * Переключение 1 <-> 2 у работающего узла: TUN подключается и снимается на лету, Link и носители не перезапускаются.
     * Режим 0 - это stopVpn. Выполняется вне главного потока (создание TUN может ждать систему).
     */
    private void switchMode(final int want) {
        mode = want;
        new Thread(() -> {
            synchronized (modeLock) {
                if (mode != want || "stopping".equals(phase) || "idle".equals(phase) || "error".equals(phase)) return;
                try {
                    if (want == 2 && tun == null) {
                        establishTun();
                        Native.setTun(tun.getFd());
                    } else if (want == 1 && tun != null) {
                        Native.setTun(-1);
                        synchronized (KnotHopVpnService.this) {
                            try { tun.close(); } catch (Throwable ignored) { }
                            tun = null;
                            excludedRouteCount = 0;
                        }
                    }
                    updateNotification(statusText());
                } catch (Throwable t) {
                    Util.svc("смена режима на " + want + " не удалась: " + t);
                    lastError = "режим VPN не включён: " + t;
                    mode = 1;
                }
            }
        }, "knothop-mode").start();
    }

    private String statusText() {
        String s = serviceKey.isEmpty() ? "" : serviceKey.split("\n", 3)[2];
        boolean up = serviceKey.startsWith("up");
        if (mode == 1) return up ? "в сети без VPN: " + s : "в сети без VPN, ищу выход";
        return up ? "подключено: " + s : "ищу выход";
    }

    /** One-time file migration on the service worker, before any native VPN command or TUN setup. */
    private void migrateLegacyRoutingBeforeNative() {
        boolean hadLegacy = RoutingCfg.load(state).hadLegacy;
        RoutingCfg.migrateLegacy(state);
        RoutingCfg after = RoutingCfg.load(state);
        if (after.hadLegacy || (hadLegacy && after.corrupt)) {
            throw new IllegalStateException("Не удалось безопасно отключить прежний рейтинг выходов; VPN не запущен");
        }
    }

    /**
     * Лаборатория (H5): имитация сбоя нативной части без падения процесса и без снятия VpnService. Файл fin нативная часть читает как
     * команду остановки и возвращает код 0, но фаза не «stopping», поэтому run() уходит в тот же путь, что и неожиданный выход (fail).
     * Нативный дескриптор TUN - дубликат (F_DUPFD_CLOEXEC), поэтому закрытие на стороне нативной части не снимает TUN у приложения.
     */
    private synchronized void labNativeFail() {
        if (tun == null || !("up".equals(phase) || "connecting".equals(phase)) || state == null) {
            Util.svc("LAB native-fail пропущен, фаза " + phase);
            return;
        }
        Util.svc("LAB native-fail: имитация сбоя нативной части");
        try { new File(state, "fin").createNewFile(); } catch (Exception ignored) { }
    }

    /**
     * H5 kill-switch: при сбое нативной части TUN не закрываем. Дескриптор остаётся открытым без чтения, маршрут по умолчанию
     * по-прежнему ведёт в него, и пакеты отбрасываются, а не уходят мимо VPN. Выход - только кнопкой «Отключить» (штатный stopVpn).
     * Если TUN ещё не создан, закрывать нечего: сервис останавливается.
     */
    private synchronized void fail(String err, Object session) {
        if (watchSession != session || "stopping".equals(phase) || "idle".equals(phase)) return;
        lastError = err;
        phase = "error";
        Util.dbg("служба: ошибка: " + err);
        stopServiceWatcher();
        if (tun == null) {
            cleanup();
            stopSelf();
            return;
        }
        tunHeld = true;
        unwatch();
        dropProfile();
        foreground("VPN не работает, трафик заблокирован");
    }

    private Builder newBuilder(String tunIp) throws Exception {
        Builder b = new Builder().setSession("KnotHop").setMtu(Util.MTU).addAddress(tunIp, 32).addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1").addDnsServer("8.8.8.8");
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
        // IPv6 туннелем не переносится: маршрут по умолчанию загоняет его в туннель, где пакеты отбрасываются (нет утечки мимо VPN).
        b.addAddress("fd99:99::2", 128).addRoute("::", 0);
        // Приложения мимо VPN (выбор пользователя): исключение исполняет система, не зависит от версии Android.
        for (String pkg : AppRules.load(new java.io.File(getFilesDir(), "state")).directPackages()) {
            try { b.addDisallowedApplication(pkg); } catch (Throwable ignored) { }   // пакет удалён - пропускаем
        }
        return b;
    }

    /**
     * Сеть для носителя: настоящая (не VPN) с интернетом. Активной сетью бывает чужой VPN или наш собственный остаточный туннель, поэтому
     * её берём, только если она не VPN, иначе ищем среди всех: сначала проверенную системой, затем любую с интернетом.
     */
    private Network physicalNetwork() {
        Network best = null;
        int bestScore = -1;
        Network active = cm.getActiveNetwork();
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities c = cm.getNetworkCapabilities(n);
            if (c == null || !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) || !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
            int score = (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? 2 : 0) + (n.equals(active) ? 1 : 0);
            if (score > bestScore) { best = n; bestScore = score; }
        }
        return best;
    }

    /** Process binding replaces UID exclusion. Never clear it while TUN exists (loop guard). */
    private void bindCarrierBeforeTun() {
        cm = (ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE);
        Network candidate = physicalNetwork();
        if (candidate == null) throw new IllegalStateException("Нет физической сети для носителя VPN");
        if (!cm.bindProcessToNetwork(candidate)) throw new IllegalStateException("Не удалось привязать носитель к сети");
        carrierNetwork = candidate;
        live = this;
    }

    static final class SpeedPath {
        final KnotHopVpnService service;
        final Object session;
        final Network network;
        final String exit;
        SpeedPath(KnotHopVpnService service, Network network) {
            this.service = service; this.session = service.watchSession; this.network = network;
            this.exit = service.serviceKey;
        }
        boolean valid() {
            synchronized (service) {
                NetworkCapabilities caps = service.cm.getNetworkCapabilities(network);
                return live == service && service.watchSession == session && service.tun != null
                        && "up".equals(phase) && !tunHeld && exit.equals(service.serviceKey)
                        && caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            }
        }
    }

    /** Only our current VPN, never the default/physical Network. Ambiguity is an error. */
    static SpeedPath speedPath() {
        KnotHopVpnService s = live;
        if (s == null) return null;
        synchronized (s) {
            if (!"up".equals(phase) || tunHeld || s.tun == null || s.watchSession == null) return null;
            // excludeRoute can intentionally bypass VPN; do not claim a through-VPN measurement in that mode.
            if (s.excludedRouteCount != 0) return null;
            Network selected = null;
            for (Network n : s.cm.getAllNetworks()) {
                NetworkCapabilities caps = s.cm.getNetworkCapabilities(n);
                if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                // getOwnerUid появился только в API 30; на Android 10 вызов ронял экран теста (NoSuchMethodError).
                if (Build.VERSION.SDK_INT >= 30 && caps.getOwnerUid() != android.os.Process.myUid()) continue;
                if (selected != null) return null;
                selected = n;
            }
            return selected == null ? null : new SpeedPath(s, selected);
        }
    }

    /** Исключает первые `n` подсетей из списка; возвращает, сколько действительно исключено. */
    private static int addExcluded(Builder b, List<String> direct, int n) {
        int done = 0;
        if (Build.VERSION.SDK_INT < 33) return 0;
        for (int i = 0; i < n && i < direct.size(); i++) {
            try {
                String[] pr = direct.get(i).split("/");
                b.excludeRoute(new IpPrefix(InetAddress.getByName(pr[0]), Integer.parseInt(pr[1])));
                done++;
            } catch (Throwable ignored) { }
        }
        return done;
    }

    /** Подсети правил «мимо VPN» (строки a.b.c.d/n) из direct.cidr, который собирает нативная часть по routing.json и файлам списков. */
    private List<String> directRoutes() {
        List<String> out = new ArrayList<>();
        try {
            new File(state, "direct.cidr").delete();
            if (!RoutingCfg.load(state).mode.equals("rules")) return out;
            if (Native.runVpn("rules-compile --state " + state.getAbsolutePath(), state.getAbsolutePath()) != 0) return out;
            for (String l : Util.read(new File(state, "direct.cidr")).split("\n")) if (l.matches("\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}")) out.add(l);
        } catch (Throwable ignored) { }
        return out;
    }

    private boolean watching(Object session) {
        return watchSession == session && ("up".equals(phase) || "connecting".equals(phase));
    }

    private synchronized void startServiceWatcher(final Object session) {
        if (!watching(session)) return;
        serviceKey = "";
        serviceObserver = new FileObserver(state.getAbsolutePath(), FileObserver.MOVED_TO | FileObserver.CLOSE_WRITE) {
            @Override public void onEvent(int event, String path) {
                if (!"service.json".equals(path)) return;
                synchronized (KnotHopVpnService.this) {
                    if (!watching(session)) return;
                    serviceUi.post(() -> reconcileService(session));
                }
            }
        };
        serviceObserver.startWatching();
        reconcileService(session); // Subscribe first, so initial publication cannot be lost.
        serviceUi.postDelayed(new Runnable() {
            @Override public void run() {
                synchronized (KnotHopVpnService.this) {
                    if (!watching(session)) return;
                    reconcileService(session);
                    serviceUi.postDelayed(this, 30_000);
                }
            }
        }, 30_000);
    }

    private synchronized void reconcileService(Object session) {
        if (!watching(session)) return;
        try {
            JSONObject j = new JSONObject(Util.read(new File(state, "service.json")));
            String st = j.optString("state");
            if (!"up".equals(st) && !"connecting".equals(st)) return;
            JSONObject cur = j.optJSONObject("current");
            String dest = cur == null ? "" : cur.optString("d");
            String name = cur == null ? "?" : cur.optString("n", "?");
            String key = st + "\n" + dest + "\n" + name;
            if (key.equals(serviceKey)) return;
            serviceKey = key;
            phase = st;
            Util.dbg("служба: фаза " + st + ", выход " + name);
            updateNotification(statusText());
        } catch (Exception ignored) { } // A missed/partial event is reconciled within 30 s.
    }

    private synchronized void stopServiceWatcher() {
        watchSession = null; // Invalidates even callbacks already queued by the old observer.
        if (serviceObserver != null) serviceObserver.stopWatching();
        serviceObserver = null;
        serviceUi.removeCallbacksAndMessages(null);
    }

    private void updateNotification(String text) {
        try { foreground(text); } catch (Throwable ignored) { }
    }

    private void registerNetworkWatcher(final Object session) {
        cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        netCb = new ConnectivityManager.NetworkCallback() {
            private void poke() {
                Util.dbg("сеть изменилась (Wi-Fi/мобильная), сообщаю нативной части");
                synchronized (KnotHopVpnService.this) {
                    if (watchSession != session) return;
                    Native.networkChanged();
                }
            }
            @Override public void onAvailable(Network n) {
                synchronized (KnotHopVpnService.this) {
                    if (watchSession != session) return;
                    NetworkCapabilities caps = cm.getNetworkCapabilities(n);
                    if (caps == null || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return;
                    if (!cm.bindProcessToNetwork(n)) { fail("Носитель потерял физическую сеть", session); return; }
                    carrierNetwork = n;
                    Util.dbg("физическая сеть доступна: " + (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ? "Wi-Fi" : caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ? "мобильная" : "другая"));
                    try { if (tun != null) setUnderlyingNetworks(new Network[]{n}); } catch (Throwable ignored) { }
                }
                poke();
            }
            @Override public void onLost(Network n) {
                // Do NOT unbind: new native sockets must not fall back into our TUN.
                Util.dbg("физическая сеть потеряна");
                poke();
            }
        };
        cm.registerNetworkCallback(new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), netCb);
    }

    private synchronized void cleanup() {
        stopServiceWatcher();
        unwatch();
        boolean closed = true;
        try { if (tun != null) tun.close(); } catch (Throwable ignored) { closed = false; }
        tun = null;
        if (closed && cm != null && carrierNetwork != null) cm.bindProcessToNetwork(null);
        carrierNetwork = null;
        if (live == this) live = null;
        tunHeld = false;
        mode = 0;
        dropProfile();
    }

    private void unwatch() {
        try { if (cm != null && netCb != null) cm.unregisterNetworkCallback(netCb); } catch (Throwable ignored) { }
        netCb = null;
    }

    /** Профиль (ключ клиента) не оставляем на диске. */
    private void dropProfile() {
        try { if (state != null) new File(state, "profile.txt").delete(); } catch (Throwable ignored) { }
    }

    private synchronized void stopVpn() {
        if ("stopping".equals(phase)) return;
        Util.dbg("служба: остановка VPN");
        final Thread w = worker;
        phase = "stopping";
        stopServiceWatcher();
        new Thread(() -> {
            try {
                if (state != null) new File(state, "fin").createNewFile();
                if (w != null) w.join(6000);
            } catch (Exception ignored) { }
            synchronized (KnotHopVpnService.this) {
                cleanup();
                phase = "idle";
                stopForeground(true);
                stopSelf();
            }
        }, "knothop-stop").start();
    }

    @Override
    public void onRevoke() {
        Util.dbg("служба: система отозвала VPN (onRevoke)");
        stopVpn();
    }

    @Override
    public void onDestroy() {
        Util.dbg("служба: onDestroy");
        cleanup();
        super.onDestroy();
    }
}
