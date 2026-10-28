package com.knothop.vpn;

import android.content.Context;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.widget.ScrollView;

/**
 * ScrollView с жестом «потяни вниз, чтобы обновить» (androidx в сборке нет). Жест начинается только у верхнего края; пока тянем,
 * содержимое не прокручивается, а слушатель получает долю натяжения (0..1). Обновление - при отпускании после полного натяжения.
 */
class PullScrollView extends ScrollView {
    interface Listener {
        void onPull(float fraction);
        void onRefresh();
        /** Страница дотянута до низа и потянута вверх: открыть журнал. */
        default void onPullUp() { }
    }

    private Listener listener;
    private final float slop, trigger;
    private float downY;
    private boolean pulling, pullingUp, ready;

    PullScrollView(Context c) {
        super(c);
        slop = ViewConfiguration.get(c).getScaledTouchSlop() * 2;
        trigger = c.getResources().getDisplayMetrics().density * 90;
    }

    void setListener(Listener l) { listener = l; }

    private boolean atBottom() {
        View c = getChildAt(0);
        return c != null && getScrollY() + getHeight() >= c.getHeight() - 4;
    }

    @Override
    public boolean onInterceptTouchEvent(MotionEvent e) {
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                downY = e.getY();
                pulling = false;
                pullingUp = false;
                ready = false;
                break;
            case MotionEvent.ACTION_MOVE:
                if (!pullingUp && listener != null && atBottom() && downY - e.getY() > slop * 2) {
                    pullingUp = true;
                    return true;
                }
                if (!pulling && listener != null && getScrollY() == 0 && e.getY() - downY > slop) {
                    pulling = true;
                    return true;
                }
                break;
            default:
                break;
        }
        return super.onInterceptTouchEvent(e);
    }

    @Override
    public boolean onTouchEvent(MotionEvent e) {
        if (e.getActionMasked() == MotionEvent.ACTION_DOWN) downY = e.getY();
        // Когда ScrollView уже перехватил прокрутку, Android больше не зовёт onInterceptTouchEvent для MOVE.
        // Поэтому достижение нижнего края проверяем и в собственном обработчике жеста.
        if (!pulling && !pullingUp && listener != null && e.getActionMasked() == MotionEvent.ACTION_MOVE
                && atBottom() && downY - e.getY() > slop * 2) pullingUp = true;
        if (pullingUp) {
            int a = e.getActionMasked();
            if (a == MotionEvent.ACTION_UP) {
                pullingUp = false;
                if (downY - e.getY() >= trigger * 0.6f) listener.onPullUp();
            } else if (a == MotionEvent.ACTION_CANCEL) {
                pullingUp = false;
            }
            return true;
        }
        if (!pulling) return super.onTouchEvent(e);
        float frac = Math.max(0f, Math.min(1f, (e.getY() - downY) / trigger));
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_MOVE:
                if (frac >= 1f && !ready) Ui.tick(this);
                ready = frac >= 1f;
                listener.onPull(frac);
                break;
            case MotionEvent.ACTION_UP:
                pulling = false;
                listener.onPull(0f);
                if (frac >= 1f) { Ui.click(this); listener.onRefresh(); }
                break;
            case MotionEvent.ACTION_CANCEL:
                pulling = false;
                listener.onPull(0f);
                break;
            default:
                break;
        }
        return true;
    }
}
