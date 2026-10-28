package com.knothop.vpn;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/** Настройки использования конкретной ноды на ЭТОМ телефоне. Не дают удалённых полномочий и не меняют выход при открытии. */
public final class NodeSettingsActivity extends Activity {
    private String target, name, fingerprint;
    private LinearLayout box;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        target = getIntent().getStringExtra(NodeAdminActivity.EXTRA_TARGET);
        name = RightsEditor.clip(getIntent().getStringExtra(NodeAdminActivity.EXTRA_NAME));
        fingerprint = getIntent().getStringExtra(NodeAdminActivity.EXTRA_FINGERPRINT);
        if (target == null || !target.matches("[0-9a-fA-F]{32}")) { finish(); return; }
        target = target.toLowerCase(java.util.Locale.ROOT);
        ScrollView scroll = new ScrollView(this);
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(32, 40, 32, 40);
        scroll.addView(box);
        setContentView(scroll);
        text("Настройки ноды", 22);
        text(name.isEmpty() ? target.substring(0, 8) : name, 18);
        if (fingerprint != null && fingerprint.matches("[0-9a-fA-F]{32}")) text("Fingerprint: " + fingerprint, 12);
        text("Настройки маршрутов действуют только на этом телефоне. Открытие экрана не переключает VPN-выход.", 14);
        button("Использовать выходом по умолчанию", () -> select(target));
        button("Выбирать выход автоматически", () -> select("auto"));
        button("Сайты и адреса через эту ноду", () -> startActivity(new Intent(this, RoutingActivity.class)
                .putExtra(RoutingActivity.EXTRA_TARGET, target).putExtra(RoutingActivity.EXTRA_NAME, name)));
        button("Все правила телефона", () -> startActivity(new Intent(this, RoutingActivity.class)));
        text("Администрирование сервера — отдельные права. Наличие USE не позволяет менять чужую ноду.", 13);
        button("Управление сервером и права", () -> startActivity(new Intent(this, NodeAdminActivity.class)
                .putExtra(NodeAdminActivity.EXTRA_TARGET, target).putExtra(NodeAdminActivity.EXTRA_NAME, name)
                .putExtra(NodeAdminActivity.EXTRA_FINGERPRINT, fingerprint)));
    }

    private void text(String value, int size) {
        TextView t = new TextView(this);
        t.setText(value); t.setTextSize(size); t.setPadding(0, 12, 0, 12); box.addView(t);
    }

    private void button(String label, Runnable action) {
        Button b = new Button(this); b.setAllCaps(false); b.setText(label);
        b.setOnClickListener(v -> { Ui.tick(v); action.run(); }); box.addView(b);
    }

    private void select(String destination) {
        try {
            File state = new File(getFilesDir(), "state"); state.mkdirs();
            File tmp = new File(state, "select.tmp");
            Files.write(tmp.toPath(), destination.getBytes(StandardCharsets.UTF_8));
            Files.move(tmp.toPath(), new File(state, "select").toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            Toast.makeText(this, destination.equals("auto") ? "Автоматический выбор выхода включён" : "Нода выбрана; подключение зависит от прав и доступности", Toast.LENGTH_LONG).show();
        } catch (Exception e) { Toast.makeText(this, "Не удалось сохранить выбор", Toast.LENGTH_LONG).show(); }
    }
}
