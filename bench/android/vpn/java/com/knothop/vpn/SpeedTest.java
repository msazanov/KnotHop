package com.knothop.vpn;

import android.net.Network;
import java.net.HttpURLConnection;
import java.util.concurrent.atomic.AtomicBoolean;

/** Foreground, user-triggered test. All sockets AND DNS are explicitly on our VPN Network. */
final class SpeedTest {
    private static final AtomicBoolean running = new AtomicBoolean();
    static volatile String text = "Тест доступен при подключённом VPN";
    static boolean running() { return running.get(); }

    static boolean start(KnotHopVpnService.SpeedPath path, String down, String up, long bytes) {
        if (path == null || !path.valid() || !running.compareAndSet(false, true)) return false;
        text = "Загрузка…";
        new Thread(() -> {
            try {
                Network network = path.network;
                SpeedTransfer.Connection factory = url -> {
                    if (!path.valid()) throw new java.io.IOException("VPN отключён или сменился");
                    for (java.net.InetAddress a : network.getAllByName(url.getHost()))
                        if (path.bypasses(a)) throw new java.io.IOException("адрес " + a.getHostAddress() + " идёт мимо VPN по правилам маршрутизации; замер через туннель невозможен");
                    return (HttpURLConnection)network.openConnection(url);
                };
                String download;
                try { download = SpeedTransfer.run(factory, path::valid, down, false, bytes, SpeedTransfer.MAX_MS).text(); }
                catch (Throwable e) { download = "Не измерено: " + e.getMessage(); }
                text = "↓ " + download + "\nОтправка…";
                try {
                    String upload = SpeedTransfer.run(factory, path::valid, up, true, bytes, SpeedTransfer.MAX_MS).text();
                    text = "↓ " + download + "\n↑ " + upload;
                } catch (Throwable e) {
                    text = "↓ " + download + "\n↑ Не измерено: " + e.getMessage();
                }
            } catch (Throwable e) {   // Error в фоновом потоке иначе роняет весь процесс
                text = "Не измерено: " + e;
            } finally { running.set(false); }
        }, "knothop-http-speed").start();
        return true;
    }
}
