package com.rawg.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.IpPrefix;
import android.net.Network;
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
 * VPN-сервис: поднимает TUN с адресом из профиля, отдаёт дескриптор нативной части (rawgd client) и следит за ней.
 * Своё приложение исключено из туннеля (addDisallowedApplication), поэтому QUIC-носитель идёт мимо VPN и не зацикливается.
 * Сервера и ключи берутся только из профиля (после спаривания), ничего не запрашивается по сети до подключения.
 */
public class RawgVpnService extends VpnService {
    static final String A_START = "com.rawg.vpn.START";
    static final String A_STOP = "com.rawg.vpn.STOP";
    /** Только лабораторная сборка (см. labNativeFail): имитация сбоя нативной части. */
    static final String A_LAB_NATIVE_FAIL = "com.rawg.vpn.LAB_NATIVE_FAIL";
    static final String EXTRA_ARGS = "args";
    private static final String CHANNEL = "rawg";

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
        if ("stopping".equals(phase) || (worker != null && worker.isAlive())) return START_NOT_STICKY;
        if (tun != null) cleanup();   // TUN, оставленный после сбоя (tunHeld), заменяем новым
        extraArgs = intent != null && intent.getStringExtra(EXTRA_ARGS) != null ? intent.getStringExtra(EXTRA_ARGS) : "";
        foreground("подключаюсь");
        state = new File(getFilesDir(), "state");
        state.mkdirs();
        File[] old = state.listFiles();
        // identity.key, trust.json и hints.json - постоянное состояние клиента (модель 0013): ключ, якоря с записями, адреса выходов; names.json - имена узлов, сообщённые ими по допущенному Link. Всё остальное - след прошлого запуска.
        java.util.Set<String> keep = new java.util.HashSet<>(java.util.Arrays.asList("identity.key", "trust.json", "hints.json", "routing.json", "names.json"));
        if (old != null) for (File f : old) if (f.isFile() && !keep.contains(f.getName())) f.delete();
        lastError = "";
        phase = "connecting";
        startedMs = System.currentTimeMillis();
        final Object session = new Object();
        watchSession = session;
        worker = new Thread(() -> run(session), "rawg-vpn");
        worker.start();
        return START_NOT_STICKY;
    }

    private void foreground(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, "rawg VPN", NotificationManager.IMPORTANCE_LOW));
        Intent stop = new Intent(this, RawgVpnService.class).setAction(A_STOP);
        PendingIntent pi = PendingIntent.getService(this, 1, stop, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent open = PendingIntent.getActivity(this, 2, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, CHANNEL).setContentTitle("rawg VPN").setContentText(text)
                .setSmallIcon(android.R.drawable.ic_lock_lock).setOngoing(true).setContentIntent(open)
                .addAction(new Notification.Action.Builder(null, "Отключить VPN", pi).build()).build();
        if (Build.VERSION.SDK_INT >= 29) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        else startForeground(1, n);
    }

    private void run(Object session) {
        Util.lab("service run() start");
        try {
            Profile prof = Profile.parse(getSharedPreferences("p", MODE_PRIVATE).getString("profile", ""));
            File pf = new File(state, "profile.txt");
            Files.write(pf.toPath(), prof.raw.getBytes(StandardCharsets.UTF_8));
            pf.setReadable(false, false);
            pf.setReadable(true, true);
            String tunIp = prof.ip;
            String clientArgs;
            if (prof.invite) {
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
            } else {
                clientArgs = "--profile-file " + pf.getAbsolutePath();
            }

            synchronized (this) {
                if (watchSession != session) return;
                phase = "tun";
            }
            Builder b;
            // раздельное туннелирование: подсети правил «мимо VPN» исключаются из туннеля (Android 13+). Нативная часть собирает их из списков
            // (самые крупные блоки первыми, не больше предела Binder). Если система всё же отказывает, берём вдвое меньше, затем без исключений.
            List<String> direct = directRoutes();
            int excluded = Build.VERSION.SDK_INT >= 33 ? direct.size() : 0;
            while (true) {
                try {
                    excluded = addExcluded(b = newBuilder(tunIp), direct, excluded);
                    tun = b.establish();
                    break;
                } catch (Throwable t) {
                    if (excluded == 0) throw t;
                    Util.lab("establish with " + excluded + " excluded failed: " + t);
                    excluded = excluded > 200 ? excluded / 2 : 0;
                }
            }
            getSharedPreferences("p", MODE_PRIVATE).edit().putString("routing_sig", RoutingCfg.load(state).directSig()).apply();
            Util.lab("excluded routes: " + excluded + " of " + direct.size());
            if (tun == null) throw new IllegalStateException("система не выдала TUN (разрешение VPN отозвано?)");

            synchronized (this) {
                if (watchSession != session) return;
                registerNetworkWatcher(session);
                phase = "connecting";
                serviceUi.post(() -> startServiceWatcher(session));
            }
            Util.lab("phase connecting, tun fd " + tun.getFd());
            String args = "client --state " + state.getAbsolutePath() + " " + clientArgs
                    + " --tun-fd " + tun.getFd() + " --fail-ms 3000 --workers 4 " + extraArgs;
            if (Util.LAB_BUILD) {
                try {
                    // Частные адреса разрешены только в явно настроенной изолированной лаборатории, не при диагностике пилота.
                    boolean localLab = !getSharedPreferences("p", MODE_PRIVATE).getString("lab_pub", "").isEmpty();
                    if (localLab) android.system.Os.setenv("RAWGD_ALLOW_PRIVATE_DIAL", "1", true);
                    else android.system.Os.unsetenv("RAWGD_ALLOW_PRIVATE_DIAL");
                    android.system.Os.setenv("RAWG_DEBUG", "1", true);
                } catch (Exception ignored) { }
            }
            int rc = Native.runVpn(args, state.getAbsolutePath());
            if (!"stopping".equals(phase)) {
                String err = Util.read(new File(state, "error.txt"));
                Util.lab("native exited rc=" + rc + " err=" + err);
                fail(err.isEmpty() ? "нативная часть завершилась (rc=" + rc + ")" : err, session);
            }
        } catch (Throwable t) {
            fail(t.toString(), session);
        }
    }

    /**
     * Лаборатория (H5): имитация сбоя нативной части без падения процесса и без снятия VpnService. Файл fin нативная часть читает как
     * команду остановки и возвращает код 0, но фаза не «stopping», поэтому run() уходит в тот же путь, что и неожиданный выход (fail).
     * Нативный дескриптор TUN - дубликат (F_DUPFD_CLOEXEC), поэтому закрытие на стороне нативной части не снимает TUN у приложения.
     */
    private synchronized void labNativeFail() {
        if (tun == null || !("up".equals(phase) || "connecting".equals(phase)) || state == null) {
            Util.lab("LAB native-fail пропущен, фаза " + phase);
            return;
        }
        Util.lab("LAB native-fail: имитация сбоя нативной части");
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
        Builder b = new Builder().setSession("rawg").setMtu(Util.MTU).addAddress(tunIp, 32).addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1").addDnsServer("8.8.8.8").setMetered(false);
        // IPv6 туннелем не переносится: маршрут по умолчанию загоняет его в туннель, где пакеты отбрасываются (нет утечки мимо VPN).
        b.addAddress("fd99:99::2", 128).addRoute("::", 0);
        b.addDisallowedApplication(getPackageName());
        return b;
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
                synchronized (RawgVpnService.this) {
                    if (!watching(session)) return;
                    serviceUi.post(() -> reconcileService(session));
                }
            }
        };
        serviceObserver.startWatching();
        reconcileService(session); // Subscribe first, so initial publication cannot be lost.
        serviceUi.postDelayed(new Runnable() {
            @Override public void run() {
                synchronized (RawgVpnService.this) {
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
            updateNotification("up".equals(st) ? "подключено: " + name : "ищу выход");
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
                synchronized (RawgVpnService.this) {
                    if (watchSession != session) return;
                    Native.networkChanged();
                }
            }
            @Override public void onAvailable(Network n) { poke(); }
            @Override public void onLost(Network n) { poke(); }
        };
        cm.registerDefaultNetworkCallback(netCb);
    }

    private synchronized void cleanup() {
        stopServiceWatcher();
        unwatch();
        try { if (tun != null) tun.close(); } catch (Throwable ignored) { }
        tun = null;
        tunHeld = false;
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
        final Thread w = worker;
        phase = "stopping";
        stopServiceWatcher();
        new Thread(() -> {
            try {
                if (state != null) new File(state, "fin").createNewFile();
                if (w != null) w.join(6000);
            } catch (Exception ignored) { }
            synchronized (RawgVpnService.this) {
                cleanup();
                phase = "idle";
                stopForeground(true);
                stopSelf();
            }
        }, "rawg-stop").start();
    }

    @Override
    public void onRevoke() {
        stopVpn();
    }

    @Override
    public void onDestroy() {
        cleanup();
        super.onDestroy();
    }
}
