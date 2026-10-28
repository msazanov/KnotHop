package com.knothop.vpn;

import android.app.Activity;
import android.content.Intent;
import android.widget.Button;
import android.widget.LinearLayout;

/** Вкладки настроек своей ноды (долгое нажатие на свой телефон на графе): «Права» и «Маршрутизация». Переключение заменяет экран без анимации. */
final class NodeTabs {
    static final int RIGHTS = 0, ROUTING = 1;

    private NodeTabs() { }

    static LinearLayout bar(Activity a, int selected) {
        LinearLayout row = new LinearLayout(a);
        row.setOrientation(LinearLayout.HORIZONTAL);
        String[] titles = {"Права и имя", "Маршрутизация"};
        Class<?>[] to = {MyNodeActivity.class, RoutingActivity.class};
        for (int i = 0; i < 2; i++) {
            Button b = new Button(a);
            b.setAllCaps(false);
            b.setText(titles[i]);
            final int k = i;
            if (i == selected) {
                b.setEnabled(false);
            } else {
                b.setOnClickListener(v -> {
                    Ui.tick(v);
                    a.startActivity(new Intent(a, to[k]).addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION));
                    a.finish();
                });
            }
            row.addView(b, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        }
        return row;
    }
}
