package com.knothop.vpn;

import android.content.Context;
import android.graphics.Typeface;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Журнал узла внизу главного экрана. По умолчанию скрыт: остаётся только полоса-ручка; открывается нажатием на неё или протягиванием
 * страницы вверх от нижнего края. Открытый журнал занимает до 60% экрана; когда появляется клавиатура (поле фильтра), журнал растягивается
 * от верхней части экрана до клавиатуры - это делает `MainActivity` через `setExpanded`.
 */
final class LogConsole extends LinearLayout {
    private static final int KEEP = 800;
    private final TextView handle, text;
    private final EditText filter;
    private final ScrollView scroll;
    private final LinearLayout body;
    private final List<String> lines = new ArrayList<>();
    private boolean open;
    private boolean expanded;
    private int maxBody;

    LogConsole(Context c) {
        super(c);
        setOrientation(VERTICAL);
        setBackgroundColor(Ui.panelBody(c));
        handle = new TextView(c);
        handle.setGravity(Gravity.CENTER);
        handle.setTextSize(12);
        handle.setPadding(0, 14, 0, 14);
        handle.setBackgroundColor(Ui.panelHandle(c));
        handle.setOnClickListener(v -> setOpen(!open));
        addView(handle, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT));

        body = new LinearLayout(c);
        body.setOrientation(VERTICAL);
        body.setVisibility(GONE);
        filter = new EditText(c);
        filter.setSingleLine(true);
        filter.setTextSize(12);
        filter.setHint("фильтр по журналу");
        filter.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int d) { }
            @Override public void onTextChanged(CharSequence s, int a, int b, int d) { }
            @Override public void afterTextChanged(Editable e) { render(); }
        });
        body.addView(filter, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT));
        scroll = new ScrollView(c);
        text = new TextView(c);
        text.setTextSize(10);
        text.setTypeface(Typeface.MONOSPACE);
        text.setTextIsSelectable(true);
        text.setPadding(12, 4, 12, 4);
        scroll.addView(text);
        body.addView(scroll, new LayoutParams(LayoutParams.MATCH_PARENT, 0, 1f));
        addView(body, new LayoutParams(LayoutParams.MATCH_PARENT, 0));
        updateHandle();
    }

    boolean isOpen() { return open; }

    /** Высота открытого журнала, если клавиатуры нет (60% экрана). */
    void setMaxBody(int px) { if (maxBody != px) { maxBody = px; applySize(); } }

    void setOpen(boolean v) {
        if (open == v) return;
        Ui.tick(this);
        open = v;
        body.setVisibility(v ? VISIBLE : GONE);
        if (!v) {
            ((android.view.inputmethod.InputMethodManager) getContext().getSystemService(Context.INPUT_METHOD_SERVICE))
                    .hideSoftInputFromWindow(filter.getWindowToken(), 0);
            filter.clearFocus();
        }
        updateHandle();
        applySize();
        if (v) { render(); scroll.post(() -> scroll.scrollTo(0, text.getHeight())); }
        requestLayout();
    }

    /** Клавиатура открыта: журнал занимает всё место между верхом экрана и клавиатурой (остальное прячет `MainActivity`). */
    void setExpanded(boolean v) {
        if (expanded == v) return;
        expanded = v;
        applySize();
        requestLayout();
    }

    private void applySize() {
        LayoutParams own = (LayoutParams) getLayoutParams();
        if (own != null) {
            if (open && expanded) { own.height = 0; own.weight = 1f; }
            else { own.height = LayoutParams.WRAP_CONTENT; own.weight = 0f; }
            setLayoutParams(own);
        }
        LayoutParams b = (LayoutParams) body.getLayoutParams();
        b.height = open ? (expanded ? 0 : Math.max(0, maxBody - handle.getMeasuredHeight())) : 0;
        b.weight = open && expanded ? 1f : 0f;
        body.setLayoutParams(b);
    }

    private void updateHandle() { handle.setText(open ? "▼ Журнал (нажмите, чтобы скрыть)" : "▲ Журнал: нажмите или потяните страницу вверх"); }

    /** Новые строки журнала узла (последние KEEP); прокрутка остаётся внизу, если пользователь не листал вверх. */
    void setLines(String[] src) {
        lines.clear();
        for (int i = Math.max(0, src.length - KEEP); i < src.length; i++) {
            String ln = src[i];
            if (ln.length() > 240) ln = ln.substring(0, 240);
            lines.add(ln);
        }
        boolean atBottom = scroll.getChildCount() == 0 || scroll.getScrollY() + scroll.getHeight() >= scroll.getChildAt(0).getHeight() - 40;
        render();
        // fullScroll(FOCUS_DOWN) отбирает фокус у поля фильтра и теряет ввод с клавиатуры.
        if (atBottom) scroll.post(() -> scroll.scrollTo(0, text.getHeight()));
    }

    private void render() {
        if (!open) return;   // скрытый журнал не перерисовываем
        String f = filter.getText().toString().trim().toLowerCase(Locale.ROOT);
        StringBuilder b = new StringBuilder();
        for (String ln : lines) if (f.isEmpty() || ln.toLowerCase(Locale.ROOT).contains(f)) b.append(ln).append('\n');
        if (!b.toString().contentEquals(text.getText())) text.setText(b);
    }
}
