package com.knothop.vpn;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Typeface;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Шторка журнала. Лежит в {@link FrameLayout} поверх экрана, закрытой видна только ручка внизу. Открывается не тапом, а жестом:
 * нажать на ручку и подержать (срабатывает вибрация), затем протянуть вверх почти до верха экрана - шторка едет за пальцем, при
 * отпускании довершает открытие или откатывается. Закрыть: потянуть ручку вниз, кнопка «✕» или «назад». В шторке - кнопки диагностики
 * («Пинг», «Скорость», «IP / регион»), переключатель отладки, фильтр и сам журнал.
 */
final class LogConsole extends LinearLayout {
    interface Actions {
        void ping();
        void speed();
        void ip();
        void debug(boolean on);
        void share();
    }

    private static final int KEEP = 800;
    private final View grabber;
    private final TextView handleText, text, diagOut, speedOut;
    private final LinearLayout handle, body;
    private final EditText filter;
    private final ScrollView scroll;
    final Button pingBtn, speedBtn, ipBtn, shareBtn;
    private final Switch debugSwitch;
    private final List<String> lines = new ArrayList<>();
    private final float slop;
    private boolean open, armed, tracking, suppressSwitch;
    private float downY, startTy;
    private float handleH;
    private Runnable longPress;
    private ValueAnimator anim;

    LogConsole(Context c, Actions act) {
        super(c);
        setOrientation(VERTICAL);
        setBackground(Ui.roundStroke(Ui.panelBody(c), Ui.STROKE, 20, c));
        slop = ViewConfiguration.get(c).getScaledTouchSlop();
        int p = Ui.dp(c, 14);

        // --- ручка
        handle = new LinearLayout(c);
        handle.setOrientation(VERTICAL);
        handle.setGravity(Gravity.CENTER_HORIZONTAL);
        handle.setPadding(p, Ui.dp(c, 8), p, Ui.dp(c, 8));
        grabber = new View(c);
        grabber.setBackground(Ui.round(Ui.STROKE, 3, c));
        handle.addView(grabber, new LayoutParams(Ui.dp(c, 44), Ui.dp(c, 5)));
        handleText = Ui.muted(c, "");
        handleText.setTextSize(12);
        handleText.setGravity(Gravity.CENTER);
        handleText.setPadding(0, Ui.dp(c, 6), 0, 0);
        handle.addView(handleText);
        handle.setOnTouchListener((v, e) -> onHandleTouch(e));
        addView(handle, new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT));

        // --- содержимое
        body = new LinearLayout(c);
        body.setOrientation(VERTICAL);
        body.setPadding(p, 0, p, p);

        LinearLayout top = new LinearLayout(c);
        top.setOrientation(HORIZONTAL);
        top.setGravity(Gravity.CENTER_VERTICAL);
        top.addView(Ui.title(c, "Журнал"), new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));
        debugSwitch = new Switch(c);
        debugSwitch.setText("Отладка");
        debugSwitch.setTextSize(13);
        debugSwitch.setOnCheckedChangeListener((v, on) -> { if (!suppressSwitch) act.debug(on); });
        top.addView(debugSwitch);
        top.addView(Ui.help(c, "Отладка", "Расширенный журнал: больше событий приложения и нативной части (снимки состояния, причины обрывов, паузы процесса). "
                + "Профиль, ключи и приглашения в журнал не попадают. Журнал лежит на телефоне и уходит наружу только по кнопке «Поделиться»."), Ui.helpParams(c));
        TextView close = Ui.text(c, "✕", 18, Ui.MUTED, true);
        close.setPadding(Ui.dp(c, 14), 0, 0, 0);
        close.setContentDescription("Закрыть журнал");
        close.setOnClickListener(v -> { Ui.tick(v); setOpen(false, true); });
        top.addView(close);
        body.addView(top);

        LinearLayout tools = new LinearLayout(c);
        tools.setOrientation(HORIZONTAL);
        pingBtn = Ui.secondary(c, "Пинг", v -> act.ping());
        speedBtn = Ui.secondary(c, "Скорость", v -> act.speed());
        ipBtn = Ui.secondary(c, "IP / регион", v -> act.ip());
        for (Button b : new Button[]{pingBtn, speedBtn, ipBtn}) {
            LayoutParams lp = new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f);
            lp.rightMargin = Ui.dp(c, 6);
            tools.addView(b, lp);
        }
        LayoutParams tp = new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
        tp.topMargin = Ui.dp(c, 8);
        body.addView(tools, tp);
        diagOut = Ui.text(c, "", 13, Ui.TEXT, false);
        diagOut.setTextIsSelectable(true);
        diagOut.setPadding(0, Ui.dp(c, 6), 0, 0);
        body.addView(diagOut);
        speedOut = Ui.text(c, "", 12, Ui.TEXT, false);
        speedOut.setTypeface(Typeface.MONOSPACE);
        speedOut.setTextIsSelectable(true);
        body.addView(speedOut);

        LinearLayout fr = new LinearLayout(c);
        fr.setOrientation(HORIZONTAL);
        fr.setGravity(Gravity.CENTER_VERTICAL);
        filter = new EditText(c);
        filter.setSingleLine(true);
        filter.setTextSize(12);
        filter.setHint("фильтр по журналу");
        filter.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int d) { }
            @Override public void onTextChanged(CharSequence s, int a, int b, int d) { }
            @Override public void afterTextChanged(Editable e) { render(); }
        });
        fr.addView(filter, new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));
        shareBtn = Ui.secondary(c, "Поделиться", v -> act.share());
        shareBtn.setVisibility(GONE);
        LayoutParams sp = new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
        sp.leftMargin = Ui.dp(c, 8);
        fr.addView(shareBtn, sp);
        body.addView(fr);

        scroll = new ScrollView(c);
        text = new TextView(c);
        text.setTextSize(10);
        text.setTypeface(Typeface.MONOSPACE);
        text.setTextIsSelectable(true);
        text.setPadding(0, Ui.dp(c, 4), 0, Ui.dp(c, 4));
        scroll.addView(text);
        body.addView(scroll, new LayoutParams(LayoutParams.MATCH_PARENT, 0, 1f));
        addView(body, new LayoutParams(LayoutParams.MATCH_PARENT, 0, 1f));
        updateHandle();
    }

    boolean isOpen() { return open; }

    TextView diagOut() { return diagOut; }
    TextView speedOut() { return speedOut; }

    void setDebugUi(boolean on) {
        suppressSwitch = true;
        debugSwitch.setChecked(on);
        suppressSwitch = false;
        shareBtn.setVisibility(on ? VISIBLE : GONE);
    }

    void setDiag(CharSequence t) { diagOut.setText(t); }

    // ---------------------------------------------------------------- шторка
    /** Размещение в FrameLayout: высота шторки задаётся владельцем, закрытое положение смещает её вниз, оставляя ручку. */
    private float closedTy() { return Math.max(0, getHeight() - handleH()); }

    private float handleH() {
        if (handle.getHeight() > 0) handleH = handle.getHeight();
        return handleH > 0 ? handleH : Ui.dp(getContext(), 44);
    }

    /** После изменения размера (клавиатура, поворот): закрытая шторка остаётся закрытой, открытая - открытой. */
    void relayout() {
        if (tracking) return;
        setTranslationY(open ? 0 : closedTy());
    }

    void setOpen(boolean v, boolean animate) {
        open = v;
        armed = false;
        tracking = false;
        if (!v) {
            ((android.view.inputmethod.InputMethodManager) getContext().getSystemService(Context.INPUT_METHOD_SERVICE))
                    .hideSoftInputFromWindow(filter.getWindowToken(), 0);
            filter.clearFocus();
        }
        updateHandle();
        float target = v ? 0 : closedTy();
        if (anim != null) anim.cancel();
        if (!animate) setTranslationY(target);
        else {
            anim = ValueAnimator.ofFloat(getTranslationY(), target);
            anim.setDuration(200);
            anim.addUpdateListener(a -> setTranslationY((float) a.getAnimatedValue()));
            anim.start();
        }
        if (v) { render(); scroll.post(() -> scroll.scrollTo(0, text.getHeight())); }
    }

    private void updateHandle() {
        handleText.setText(open ? "Журнал открыт · потяните вниз, чтобы закрыть" : "Журнал · удерживайте и тяните вверх");
        grabber.setBackground(Ui.round(armed ? Ui.ORANGE : Ui.STROKE, 3, getContext()));
    }

    private boolean onHandleTouch(MotionEvent e) {
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                if (anim != null) anim.cancel();
                downY = e.getRawY();
                startTy = getTranslationY();
                tracking = false;
                armed = open;       // открытую шторку можно тянуть сразу, закрытую - только после удержания
                if (!open) {
                    longPress = () -> { armed = true; Ui.click(handle); updateHandle(); };
                    handle.postDelayed(longPress, ViewConfiguration.getLongPressTimeout());
                }
                handle.getParent().requestDisallowInterceptTouchEvent(true);
                return true;
            case MotionEvent.ACTION_MOVE: {
                float dy = e.getRawY() - downY;
                if (!armed) {
                    // двинули палец до срабатывания удержания: это не жест открытия
                    if (Math.abs(dy) > slop * 2 && longPress != null) { handle.removeCallbacks(longPress); longPress = null; }
                    return true;
                }
                tracking = true;
                setTranslationY(Math.max(0, Math.min(closedTy(), startTy + dy)));
                return true;
            }
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                if (longPress != null) { handle.removeCallbacks(longPress); longPress = null; }
                boolean was = tracking;
                tracking = false;
                if (!was) { armed = false; updateHandle(); return true; }   // короткий тап ничего не открывает
                float frac = closedTy() == 0 ? 0 : getTranslationY() / closedTy();
                // открыто, если протянули выше 30% от закрытого положения (то есть дальше 70% пути вверх); открытую - закрываем, когда ушла ниже 30%
                boolean toOpen = e.getActionMasked() == MotionEvent.ACTION_UP && (open ? frac < 0.3f : frac < 0.3f);
                setOpen(toOpen, true);
                return true;
            default:
                return true;
        }
    }

    // ---------------------------------------------------------------- журнал
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
