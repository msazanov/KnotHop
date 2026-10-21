package com.rawg.vpn;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.widget.Toast;

/**
 * Системное подтверждение личности (отпечаток или PIN/пароль/графический ключ экрана блокировки) перед выпуском приглашения.
 * Android 11+: BiometricPrompt с резервом на учётные данные устройства; ниже: экран блокировки через Keyguard.
 * Подтверждение пропускают лабораторная сборка и сборка с Util.ADMIN_CONFIRM=false (временное решение владельца для MVP).
 */
final class Confirm {
    static final int REQ = 3;
    private static Runnable pending;

    private Confirm() { }

    static void ask(Activity a, String why, Runnable ok) {
        if (Util.LAB_BUILD || !Util.ADMIN_CONFIRM) { ok.run(); return; }
        KeyguardManager km = (KeyguardManager) a.getSystemService(Context.KEYGUARD_SERVICE);
        if (!km.isDeviceSecure()) {
            Toast.makeText(a, "Выдача приглашений требует блокировки экрана: задайте PIN, пароль или отпечаток в настройках телефона", Toast.LENGTH_LONG).show();
            return;
        }
        if (Build.VERSION.SDK_INT >= 30) {
            int auth = BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL;
            BiometricManager bm = a.getSystemService(BiometricManager.class);
            if (bm.canAuthenticate(auth) != BiometricManager.BIOMETRIC_SUCCESS) {
                Toast.makeText(a, "Подтверждение личности недоступно на этом телефоне", Toast.LENGTH_LONG).show();
                return;
            }
            BiometricPrompt prompt = new BiometricPrompt.Builder(a)
                    .setTitle(why)
                    .setSubtitle("Подтвердите, что приглашение выдаёте вы")
                    .setAllowedAuthenticators(auth)
                    .build();
            prompt.authenticate(new CancellationSignal(), a.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) { ok.run(); }
                @Override public void onAuthenticationError(int code, CharSequence msg) {
                    if (code != BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED && code != BiometricPrompt.BIOMETRIC_ERROR_CANCELED) {
                        Toast.makeText(a, "Не подтверждено: " + msg, Toast.LENGTH_SHORT).show();
                    }
                }
            });
        } else {
            Intent i = km.createConfirmDeviceCredentialIntent(why, "Подтвердите, что приглашение выдаёте вы");
            if (i == null) {
                Toast.makeText(a, "Подтверждение личности недоступно на этом телефоне", Toast.LENGTH_LONG).show();
                return;
            }
            pending = ok;
            a.startActivityForResult(i, REQ);
        }
    }

    /** Вызывать из onActivityResult активности, которая звала ask (старые Android). */
    static void onResult(int req, int res) {
        if (req != REQ) return;
        Runnable r = pending;
        pending = null;
        if (res == Activity.RESULT_OK && r != null) r.run();
    }
}
