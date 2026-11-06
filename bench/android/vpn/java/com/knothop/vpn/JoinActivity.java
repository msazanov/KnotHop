package com.knothop.vpn;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Экран «Вступить»: строка приглашения (вставка или QR). Доступен всегда, в том числе на уже настроенном телефоне и при выключенной «Сети»:
 * нода может состоять в нескольких несвязанных сетях. Окно закрыто от скриншотов, записи экрана и превью (FLAG_SECURE), пока видно поле.
 */
public final class JoinActivity extends Activity {
    private static final int REQ_SCAN = 4;
    private EditText field;
    private TextView msg;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        setTitle("Вступить по приглашению");
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Ui.BG);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(Ui.dp(this, 16), Ui.dp(this, 20), Ui.dp(this, 16), Ui.dp(this, 24));
        scroll.addView(box);
        setContentView(scroll);
        LinearLayout card = Ui.card(this);
        card.addView(Ui.titleWithHelp(this, "Приглашение",
                "Вставьте строку приглашения или отсканируйте QR. Приглашение одноразовое, срок задаёт приглашающий. Можно вступать в несколько сетей: "
                + "новая строка добавляется к уже принятым, ничего не сбрасывается. Если «Сеть» выключена, телефон погасит приглашение, когда вы её включите."));
        field = new EditText(this);
        field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        field.setMinLines(3);
        field.setGravity(Gravity.TOP);
        field.setHint("строка приглашения");
        field.setTextSize(11);
        card.addView(field, lp(8));
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams half = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        half.rightMargin = Ui.dp(this, 8);
        row.addView(Ui.secondary(this, "Вставить", v -> {
            ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData d = cb.getPrimaryClip();
            if (d != null && d.getItemCount() > 0 && d.getItemAt(0).getText() != null) field.setText(d.getItemAt(0).getText());
        }), half);
        android.widget.Button join = Ui.primary(this, "Вступить", v -> JoinFlow.confirmAndJoin(this, field.getText().toString(), ok -> {
            if (ok) { field.setText(""); finish(); }
        }));
        join.setFilterTouchesWhenObscured(true);   // F8
        row.addView(join, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        card.addView(row, lp(8));
        card.addView(Ui.secondary(this, "Сканировать QR", v -> startActivityForResult(new Intent(this, ScanActivity.class), REQ_SCAN)), lp(8));
        msg = Ui.text(this, "", 13, Ui.ORANGE, false);
        card.addView(msg, lp(6));
        box.addView(card);
    }

    private LinearLayout.LayoutParams lp(int top) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        p.topMargin = Ui.dp(this, top);
        return p;
    }

    @Override protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_SCAN && res == RESULT_OK && data != null) {
            String t = data.getStringExtra(ScanActivity.EXTRA_TEXT);
            if (t != null) {
                field.setText(t);
                msg.setText("QR считан. Проверьте и нажмите «Вступить»");
            }
        }
    }

    @Override protected void onStop() {
        super.onStop();
        // строка не должна жить в закрытом экране: пины живут только в ядре
        if (isFinishing()) field.setText("");
    }
}
