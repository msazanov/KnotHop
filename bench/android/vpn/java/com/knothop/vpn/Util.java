package com.knothop.vpn;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

final class Util {
    /** Лабораторная сборка (build.sh с KNOTHOP_LAB=1 меняет значение): управление по интентам и подробные логи. В обычной сборке выключено. */
    static final boolean LAB_BUILD = false;

    static void lab(String msg) {
        if (LAB_BUILD) android.util.Log.i("knothopui", msg);
    }

    /** Единственное, что зашито в приложении (модель 0013): публичные узлы RNS для анонсов и первого Link. Данные через них не идут. Источник: deploy-pilot/public_rns.txt (rns_ok=True). */
    static final String PUBLIC_RNS = "catz.rns.moscow:4242\n46.188.15.32:4242\n185.9.77.240:4242\n217.70.19.114:4242\n";

    static final int MTU = 1327;

    static String read(File f) {
        try {
            return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}
