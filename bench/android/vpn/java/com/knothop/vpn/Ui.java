package com.knothop.vpn;

import android.app.AlertDialog;
import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Единое место стиля: палитра (тёмная тема, акценты оранжевый и зелёный), карточки, кнопки, значок «?» и виброотклик.
 * Тема всегда тёмная (res/values и values-night одинаковы), поэтому {@link #dark} всегда true: старые экраны получают светлый текст через {@link #ink}.
 */
final class Ui {
    private Ui() { }

    // ---------------------------------------------------------------- палитра
    static final int BG = 0xFF0D0E11;
    static final int CARD = 0xFF16181D;
    static final int CARD_HI = 0xFF1F2229;
    static final int STROKE = 0xFF2A2E37;
    static final int TEXT = 0xFFECEEF2;
    static final int MUTED = 0xFF9BA1AE;
    static final int ORANGE = 0xFFFF9F43;
    static final int GREEN = 0xFF4ADE80;
    static final int RED = 0xFFFF6B6B;
    static final int ON_ACCENT = 0xFF14100A;

    static boolean dark(Context c) { return true; }

    static int dp(Context c, float v) { return (int) (v * c.getResources().getDisplayMetrics().density + 0.5f); }

    /** Явные цвета старых экранов: контрастный текст для тёмного фона, включая статусы. */
    static int ink(Context c, int color) {
        switch (color) {
            case 0xFF1F7A3A: case 0xFF1E7A3A: case 0xFF2E9E4F: return GREEN;
            case 0xFF8A4B00: case 0xFFB36B00: return ORANGE;
            case 0xFFB33A3A: return RED;
            case 0xFF3478C6: return 0xFF8AB8FF;
            default: break;
        }
        int r = (color >> 16) & 0xFF, g = (color >> 8) & 0xFF, b = color & 0xFF;
        if (Math.abs(r - g) > 12 || Math.abs(g - b) > 12) return color;
        int shade = Math.max(170, 255 - r);
        return (color & 0xFF000000) | (shade << 16) | (shade << 8) | shade;
    }

    static int fg(Context c) { return TEXT; }
    static int panel(Context c) { return CARD; }
    static int panelHandle(Context c) { return CARD_HI; }
    static int panelBody(Context c) { return 0xFF101216; }
    static int warnBg(Context c) { return 0xFF3A2A12; }
    static int green(Context c) { return GREEN; }
    static int warn(Context c) { return ORANGE; }

    // ---------------------------------------------------------------- фоны и карточки
    static GradientDrawable round(int fill, float radiusDp, Context c) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(c, radiusDp));
        return g;
    }

    static GradientDrawable roundStroke(int fill, int stroke, float radiusDp, Context c) {
        GradientDrawable g = round(fill, radiusDp, c);
        g.setStroke(Math.max(1, dp(c, 1)), stroke);
        return g;
    }

    /** Карточка: вертикальный контейнер с закруглённым фоном и отступами. */
    static LinearLayout card(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setBackground(roundStroke(CARD, STROKE, 16, c));
        l.setPadding(dp(c, 16), dp(c, 14), dp(c, 16), dp(c, 14));
        return l;
    }

    static LinearLayout.LayoutParams cardParams(Context c) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(c, 12);
        return lp;
    }

    // ---------------------------------------------------------------- текст
    static TextView text(Context c, CharSequence s, float sp, int color, boolean bold) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    static TextView title(Context c, CharSequence s) { return text(c, s, 16, TEXT, true); }
    static TextView muted(Context c, CharSequence s) { return text(c, s, 13, MUTED, false); }

    /** Заголовок карточки со значком «?» справа: пояснение открывается по тапу. */
    static LinearLayout titleWithHelp(Context c, CharSequence title, String help) {
        LinearLayout row = new LinearLayout(c);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.addView(title(c, title));
        if (help != null && !help.isEmpty()) row.addView(help(c, title.toString(), help), helpParams(c));
        return row;
    }

    static LinearLayout.LayoutParams helpParams(Context c) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(c, 26), dp(c, 26));
        lp.leftMargin = dp(c, 8);
        return lp;
    }

    /** Маленький значок «?»: тап показывает пояснение. Все длинные тексты интерфейса прячутся за ним. */
    static View help(Context c, String title, String message) {
        TextView t = new TextView(c);
        t.setText("?");
        t.setTextSize(13);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setGravity(Gravity.CENTER);
        t.setTextColor(ORANGE);
        t.setBackground(roundStroke(0x00000000, ORANGE, 13, c));
        t.setContentDescription("Пояснение: " + title);
        t.setClickable(true);
        t.setOnClickListener(v -> {
            tick(v);
            new AlertDialog.Builder(c).setTitle(title).setMessage(message).setPositiveButton("OK", null).show();
        });
        return t;
    }

    // ---------------------------------------------------------------- кнопки
    /** Основная кнопка (оранжевая заливка). */
    static Button primary(Context c, CharSequence s, View.OnClickListener l) {
        return styled(c, s, ORANGE, ON_ACCENT, 0, l);
    }

    /** Вторичная кнопка (контур). */
    static Button secondary(Context c, CharSequence s, View.OnClickListener l) {
        return styled(c, s, CARD_HI, TEXT, STROKE, l);
    }

    static Button good(Context c, CharSequence s, View.OnClickListener l) {
        return styled(c, s, GREEN, ON_ACCENT, 0, l);
    }

    private static Button styled(Context c, CharSequence s, int fill, int fg, int stroke, View.OnClickListener l) {
        Button b = new Button(c);
        b.setAllCaps(false);
        b.setText(s);
        b.setTextSize(14);
        b.setTextColor(fg);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setStateListAnimator(null);
        b.setBackground(stroke == 0 ? round(fill, 12, c) : roundStroke(fill, stroke, 12, c));
        b.setMinHeight(dp(c, 44));
        b.setMinimumHeight(dp(c, 44));
        b.setPadding(dp(c, 14), 0, dp(c, 14), 0);
        if (l != null) b.setOnClickListener(v -> { tick(v); l.onClick(v); });
        return b;
    }

    // ---------------------------------------------------------------- отклик
    /** Лёгкий отклик (уважает системную настройку «вибрация при касании»). */
    static void tick(View v) {
        if (v != null) v.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK);
    }

    /** Чуть сильнее: подтверждение выбранного режима и срабатывание жеста. */
    static void click(View v) {
        if (v == null) return;
        v.performHapticFeedback(android.os.Build.VERSION.SDK_INT >= 30 ? HapticFeedbackConstants.CONFIRM : HapticFeedbackConstants.VIRTUAL_KEY);
    }
}
