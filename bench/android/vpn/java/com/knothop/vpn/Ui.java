package com.knothop.vpn;

import android.content.Context;
import android.content.res.Configuration;
import android.view.HapticFeedbackConstants;
import android.view.View;

/** Тема (светлая/тёмная берётся из системы, ресурсы values/values-night) и лёгкий виброотклик. */
final class Ui {
    private Ui() { }

    static boolean dark(Context c) {
        return (c.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
    }

    /** Явные цвета старых экранов: контрастный текст для чёрного фона, включая статусы. */
    static int ink(Context c, int color) {
        if (!dark(c)) return color;
        switch (color) {
            case 0xFF1F7A3A: case 0xFF1E7A3A: case 0xFF2E9E4F: return green(c);
            case 0xFF8A4B00: case 0xFFB36B00: return warn(c);
            case 0xFFB33A3A: return 0xFFFF8585;
            case 0xFF3478C6: return 0xFF8AB8FF;
            default: break;
        }
        int r = (color >> 16) & 0xFF, g = (color >> 8) & 0xFF, b = color & 0xFF;
        if (Math.abs(r - g) > 12 || Math.abs(g - b) > 12) return color;
        int shade = Math.max(170, 255 - r);
        return (color & 0xFF000000) | (shade << 16) | (shade << 8) | shade;
    }

    /** Основной цвет текста темы. */
    static int fg(Context c) { return dark(c) ? 0xFFEDEDED : 0xFF1B1B1B; }

    /** Панели и полосы поверх фона. */
    static int panel(Context c) { return dark(c) ? 0xFF26262A : 0xFFEEEEEE; }
    static int panelHandle(Context c) { return dark(c) ? 0xFF33333A : 0xFFE0E0E0; }
    static int panelBody(Context c) { return dark(c) ? 0xFF1A1A1D : 0xFFF7F7F7; }

    /** Фон предупреждающего блока. */
    static int warnBg(Context c) { return dark(c) ? 0xFF4A3B12 : 0xFFFFF3D6; }

    /** Зелёный и оранжевый, читаемые на обеих темах. */
    static int green(Context c) { return dark(c) ? 0xFF5FD38A : 0xFF1F7A3A; }
    static int warn(Context c) { return dark(c) ? 0xFFFFB454 : 0xFF8A4B00; }

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
