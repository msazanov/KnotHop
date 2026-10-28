package com.knothop.vpn;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Приложения, которые идут мимо VPN. Действует при следующем подключении; работает на любой версии Android. */
public final class AppsActivity extends Activity {
    private static final class App {
        final String pkg, label;
        App(String pkg, String label) { this.pkg = pkg; this.label = label; }
    }

    private final List<App> apps = new ArrayList<>();
    private AppRules rules;
    private File state;
    private LinearLayout list;
    private String filter = "";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        state = new File(getFilesDir(), "state");
        rules = AppRules.load(state);
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 40, 32, 40);
        scroll.addView(root);
        setContentView(scroll);
        TextView title = new TextView(this);
        title.setText("Приложения мимо VPN"); title.setTextSize(22);
        root.addView(title);
        TextView hint = new TextView(this);
        hint.setText("Отмеченные приложения ходят в сеть напрямую, минуя туннель (это делает система, работает на Android 12). "
                + "Изменения вступают в силу при следующем включении VPN. Связь KnotHop с нодами от этого не зависит.");
        hint.setTextSize(13); hint.setPadding(0, 12, 0, 12);
        root.addView(hint);
        EditText search = new EditText(this);
        search.setHint("поиск по названию или пакету"); search.setSingleLine(true);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int c, int d) { }
            @Override public void onTextChanged(CharSequence s, int a, int c, int d) { }
            @Override public void afterTextChanged(Editable s) { filter = s.toString().trim().toLowerCase(Locale.ROOT); render(); }
        });
        root.addView(search);
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        root.addView(list);
        loadApps();
        render();
    }

    private void loadApps() {
        PackageManager pm = getPackageManager();
        Intent launcher = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (ResolveInfo ri : pm.queryIntentActivities(launcher, 0)) {
            String p = ri.activityInfo.packageName;
            if (p.equals(getPackageName()) || !seen.add(p)) continue;
            apps.add(new App(p, String.valueOf(ri.loadLabel(pm))));
        }
        // ранее отмеченные пакеты показываем даже если они больше не видны (удалены или скрыты)
        for (String p : rules.apps.keySet()) {
            if (seen.add(p)) apps.add(new App(p, p));
        }
        Collections.sort(apps, (a, c) -> a.label.compareToIgnoreCase(c.label));
    }

    private void render() {
        list.removeAllViews();
        int shown = 0;
        for (App a : apps) {
            String key = (a.label + " " + a.pkg).toLowerCase(Locale.ROOT);
            if (!filter.isEmpty() && !key.contains(filter)) continue;
            if (++shown > 400) break;
            String action = rules.apps.get(a.pkg);
            if (action != null && !AppRules.DIRECT.equals(action)) continue;   // назначенные на ноду здесь не меняем
            CheckBox cb = new CheckBox(this);
            cb.setText(a.label.equals(a.pkg) ? a.pkg : a.label + "\n" + a.pkg);
            cb.setChecked(AppRules.DIRECT.equals(action));
            cb.setOnCheckedChangeListener((v, on) -> {
                rules.set(a.pkg, on ? AppRules.DIRECT : null);
                try { rules.save(state); }
                catch (Exception e) { Toast.makeText(this, "Не удалось сохранить", Toast.LENGTH_LONG).show(); }
            });
            list.addView(cb);
        }
        if (shown == 0) {
            TextView t = new TextView(this); t.setText("Ничего не найдено"); list.addView(t);
        }
    }
}
