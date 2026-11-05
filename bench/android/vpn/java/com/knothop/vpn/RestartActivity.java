package com.knothop.vpn;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Process;

/**
 * Перезапуск процесса приложения (схема ProcessPhoenix). Живёт в отдельном процессе ":restart": главный процесс запускает эту
 * активность и убивает себя, активность убеждается, что старый процесс мёртв, поднимает MainActivity в новом процессе и завершается.
 * Нужна, потому что нативная часть (глобальные приёмники транспортов, mesh-таблицы, dataplane) за один процесс запускается один раз.
 */
public class RestartActivity extends Activity {
    static final String EXTRA_PID = "main_pid";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        int main = getIntent().getIntExtra(EXTRA_PID, 0);
        if (main > 0 && main != Process.myPid()) {
            try { Process.killProcess(main); } catch (Throwable ignored) { }   // уже мёртв - ничего не делает
        }
        startActivity(new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK));
        finish();
        overridePendingTransition(0, 0);
        Process.killProcess(Process.myPid());
    }
}
