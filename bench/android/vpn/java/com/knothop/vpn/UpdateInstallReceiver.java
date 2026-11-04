package com.knothop.vpn;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;

/** Результат PackageInstaller. Не exported: получает только собственный PendingIntent приложения. */
public final class UpdateInstallReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent in) {
        if (in == null || !AppUpdater.ACTION_RESULT.equals(in.getAction())) return;
        int status = in.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            // Системное окно подтверждения установки.
            Intent confirm = in.getParcelableExtra(Intent.EXTRA_INTENT);
            if (confirm != null) {
                try { c.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); }
                catch (Exception e) { AppUpdater.onResult(c, PackageInstaller.STATUS_FAILURE, "не удалось открыть подтверждение"); }
            }
            return;
        }
        AppUpdater.onResult(c, status, in.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE));
    }
}
