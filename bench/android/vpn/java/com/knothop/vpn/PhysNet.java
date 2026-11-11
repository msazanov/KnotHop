package com.knothop.vpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;

/**
 * Физическая сеть (не VPN, с интернетом) и HTTP через неё. Обновление приложения, проверка версии и геоданные не должны зависеть от
 * bindProcessToNetwork: его нет при чужом VPN или остановленной службе, а DNS через мёртвый туннель не отвечает.
 */
final class PhysNet {
    private PhysNet() { }

    /**
     * Настоящая сеть: не VPN, с интернетом; предпочтительно проверенная системой, затем активная. null, если такой нет.
     * Активной сетью бывает чужой VPN или наш остаточный туннель, поэтому её берём, только если она не VPN.
     */
    static Network find(ConnectivityManager cm) {
        if (cm == null) return null;
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

    /** Соединение через физическую сеть (DNS тоже её); если физической сети нет, обычный путь. */
    static URLConnection open(URL url) throws IOException {
        Network n = physical();
        return n != null ? n.openConnection(url) : url.openConnection();
    }

    private static Network physical() {
        try {
            Context c = Util.app;
            if (c != null) return find((ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE));
        } catch (Throwable ignored) { }
        return null;
    }

    /**
     * Сколько разных путей стоит пробовать: 2, если есть физическая сеть (тогда второй путь - обычный маршрут процесса, то есть
     * через VPN, когда он поднят), иначе 1. Провайдер может резать GitHub на физической сети, а через туннель он доступен.
     */
    static int routes() { return physical() != null ? 2 : 1; }

    /** Путь `route`: 0 - как {@link #open}, 1 - обычный маршрут процесса (через VPN, если он есть). */
    static URLConnection open(URL url, int route) throws IOException {
        return route == 0 ? open(url) : url.openConnection();
    }

    /** Короткая человеческая причина сетевой ошибки (без имён классов и адресов). */
    static String why(Throwable e) {
        if (e instanceof UnknownHostException || e instanceof NoRouteToHostException || e instanceof ConnectException) return "нет сети";
        if (e instanceof SocketTimeoutException) return "сервер не отвечает";
        if (e instanceof javax.net.ssl.SSLException) return "ошибка защищённого соединения";
        if (e instanceof IOException) return "ошибка соединения";
        return "непонятный ответ";
    }
}
