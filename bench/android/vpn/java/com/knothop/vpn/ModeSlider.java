package com.knothop.vpn;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.animation.DecelerateInterpolator;

/**
 * Переключатель режимов «Откл. / Сеть / VPN»: дорожка с тремя точками притяжения и ручкой, которая плавно переезжает и меняет цвет
 * (серый - оранжевый - зелёный). Работает и тапом по позиции (на MIUI свайп по SeekBar не срабатывает, а тап - да), и перетаскиванием.
 * Собственная отрисовка и обработка касаний: никаких SeekBar. Дорожка отстоит от краёв не меньше чем на 28 dp (жесты системы у края).
 *
 * Первое касание после открытия на MIUI (2409BRN2CG, 2510DRA23E) терялось, на Honor - нет. Разбор по коду (06.11): ползунок лежит в панели
 * ВНЕ PullScrollView и шторки журнала (соседи в общем LinearLayout), requestDisallowIntercept безвреден, getWidth к первому касанию уже
 * известен, таймер {@code setMode} лишь возвращает ручку на фактический режим и выбор не сбрасывает. Единственная причина в коде, способная
 * молча съесть ровно первое касание, - {@code setFilterTouchesWhenObscured(true)} (защита от подмены касаний, F8): MIUI держит поверх окна
 * приложения свои накладки (индикатор жестов, плашки), и пока окно «перекрыто», система выбрасывает касание до {@link #onTouchEvent}.
 * Это ГИПОТЕЗА, на устройстве не проверена. Защиту не снимаем (тапджекинг мог бы выключить VPN), но теперь отброшенное касание видно:
 * пользователь получает подсказку, а при включённой отладке счётчик и флаги события пишутся в журнал, чтобы следующий прогон на MIUI
 * показал причину. Вторая правка: разрешение на уведомления просится один раз, а не при каждом запуске (системный диалог забирал фокус окна).
 */
final class ModeSlider extends View {
    interface Listener { void onSelected(int mode); }

    static final int[] COLORS = {0xFF6C7280, Ui.ORANGE, Ui.GREEN};
    private static final String[] LABELS = {"Откл.", "Сеть", "VPN"};

    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF rect = new RectF();
    private final float dp, slop;
    private final float inset, knobR, trackH;
    private float pos;            // 0..2, текущее положение ручки
    private int mode;             // подтверждённая позиция
    private boolean dragging;
    private float downX, downPos;
    private boolean moved;
    private ValueAnimator anim;
    private Listener listener;
    private int lastStep;

    private int downs, dropped;
    private long lastNotice;

    /** Счётчики касаний для журнала отладки: всего ACTION_DOWN дошло до View / отброшено системой как «окно перекрыто». */
    @Override
    public boolean onFilterTouchEventForSecurity(MotionEvent e) {
        boolean ok = super.onFilterTouchEventForSecurity(e);
        if (e.getActionMasked() == MotionEvent.ACTION_DOWN) {
            if (ok) downs++; else dropped++;
            Util.dbg("ползунок: касание " + (ok ? "принято" : "ОТБРОШЕНО (окно перекрыто другим окном)") + ", flags=0x" + Integer.toHexString(e.getFlags())
                    + ", принято " + downs + ", отброшено " + dropped);
            if (!ok && System.currentTimeMillis() - lastNotice > 3000) {
                lastNotice = System.currentTimeMillis();
                android.widget.Toast.makeText(getContext(), "Касание не принято: поверх приложения другое окно. Повторите", android.widget.Toast.LENGTH_SHORT).show();
            }
        }
        return ok;
    }

    ModeSlider(Context c) {
        super(c);
        dp = c.getResources().getDisplayMetrics().density;
        slop = ViewConfiguration.get(c).getScaledTouchSlop();
        inset = 36 * dp;      // середина крайних точек от края view; запас больше 28 dp
        knobR = 17 * dp;
        trackH = 10 * dp;
        setMinimumHeight((int) (84 * dp));
        setFilterTouchesWhenObscured(true);
        setContentDescription("Режим: отключено, сеть без VPN или VPN");
        paint.setTextAlign(Paint.Align.CENTER);
    }

    void setListener(Listener l) { listener = l; }

    int mode() { return mode; }

    boolean isDragging() { return dragging; }

    /** Текущее положение извне (состояние службы): плавно переезжает, пока пользователь не держит ручку. */
    void setMode(int m, boolean animate) {
        mode = m;
        lastStep = m;
        if (dragging) return;
        glideTo(m, animate);
    }

    private void glideTo(float target, boolean animate) {
        if (anim != null) anim.cancel();
        if (!animate || Math.abs(pos - target) < 0.001f) { pos = target; invalidate(); return; }
        anim = ValueAnimator.ofFloat(pos, target);
        anim.setDuration((long) (140 + 120 * Math.abs(pos - target)));
        anim.setInterpolator(new DecelerateInterpolator(1.6f));
        anim.addUpdateListener(a -> { pos = (float) a.getAnimatedValue(); invalidate(); });
        anim.start();
    }

    @Override
    protected void onMeasure(int w, int h) {
        int hh = (int) (84 * dp);
        setMeasuredDimension(resolveSize(getSuggestedMinimumWidth(), w), resolveSize(hh, h));
    }

    private float x0() { return inset; }
    private float x1() { return getWidth() - inset; }
    private float xOf(float p) { return x0() + (x1() - x0()) * p / 2f; }
    private float cy() { return 30 * dp; }

    private int colorAt(float p) {
        int a = (int) Math.floor(Math.max(0, Math.min(1.999f, p)));
        float f = p - a;
        return (Integer) new ArgbEvaluator().evaluate(Math.max(0, Math.min(1, f)), COLORS[a], COLORS[Math.min(2, a + 1)]);
    }

    @Override
    protected void onDraw(Canvas c) {
        float cy = cy();
        int col = colorAt(pos);
        // дорожка
        paint.setStyle(Paint.Style.FILL);
        paint.setColor(Ui.CARD_HI);
        rect.set(x0() - knobR, cy - trackH / 2, x1() + knobR, cy + trackH / 2);
        c.drawRoundRect(rect, trackH / 2, trackH / 2, paint);
        // заполненная часть до ручки
        paint.setColor((col & 0xFFFFFF) | 0x66000000);
        rect.set(x0() - knobR, cy - trackH / 2, xOf(pos), cy + trackH / 2);
        c.drawRoundRect(rect, trackH / 2, trackH / 2, paint);
        // точки притяжения
        for (int i = 0; i < 3; i++) {
            paint.setColor(i <= pos + 0.05f ? (col & 0xFFFFFF) | 0xFF000000 : Ui.STROKE);
            c.drawCircle(xOf(i), cy, 4 * dp, paint);
        }
        // ручка
        float kx = xOf(pos);
        paint.setColor(0x44000000);
        c.drawCircle(kx, cy + 2 * dp, knobR + 1.5f * dp, paint);
        paint.setColor(col);
        c.drawCircle(kx, cy, knobR + (dragging ? 2 * dp : 0), paint);
        paint.setColor(Ui.ON_ACCENT);
        c.drawCircle(kx, cy, 5 * dp, paint);
        // подписи
        paint.setTextSize(13 * dp);
        for (int i = 0; i < 3; i++) {
            float near = Math.max(0f, 1f - Math.abs(pos - i));
            paint.setTypeface(near > 0.5f ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
            paint.setColor(near > 0.5f ? col : Ui.MUTED);
            c.drawText(LABELS[i], xOf(i), cy + knobR + 26 * dp, paint);
        }
    }

    private static int nearest(float p) { return Math.max(0, Math.min(2, Math.round(p))); }

    private float posAt(float x) { return Math.max(0f, Math.min(2f, (x - x0()) / (x1() - x0()) * 2f)); }

    @Override
    public boolean onTouchEvent(MotionEvent e) {
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                if (anim != null) anim.cancel();
                downX = e.getX();
                downPos = pos;
                moved = false;
                getParent().requestDisallowInterceptTouchEvent(true);
                return true;
            case MotionEvent.ACTION_MOVE:
                if (!moved && Math.abs(e.getX() - downX) > slop) {
                    // перетаскивание начинается только если касание пришлось на ручку или рядом с ней
                    if (Math.abs(downX - xOf(downPos)) <= knobR * 2.2f) { moved = true; dragging = true; }
                    else return true;
                }
                if (moved) {
                    pos = posAt(e.getX());
                    int step = nearest(pos);
                    if (step != lastStep) { Ui.tick(this); lastStep = step; }
                    invalidate();
                }
                return true;
            case MotionEvent.ACTION_UP: {
                boolean wasDrag = moved;
                dragging = false;
                int target = wasDrag ? nearest(pos) : nearest(posAt(e.getX()));   // тап по позиции: ближайшая точка
                if (!wasDrag && Math.abs(e.getX() - downX) > slop * 2) target = mode;
                choose(target);
                return true;
            }
            case MotionEvent.ACTION_CANCEL:
                dragging = false;
                glideTo(mode, true);
                return true;
            default:
                return true;
        }
    }

    private void choose(int target) {
        glideTo(target, true);
        lastStep = target;
        if (target != mode) {
            Ui.click(this);
            if (listener != null) listener.onSelected(target);
        }
    }
}
