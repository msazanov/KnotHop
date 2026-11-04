package com.knothop.vpn;

import android.content.Context;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.widget.ScrollView;

/**
 * ScrollView с жестом «потяни вниз, чтобы обновить» (androidx в сборке нет). Жест начинается только у верхнего края. Содержимое едет
 * за пальцем (с затуханием), под ним открывается подсказка, которую рисует владелец; слушатель получает долю натяжения (0..1+).
 * Пока палец держит дальше порога, подсказка говорит «Отпустите, чтобы обновить»; обновление запускается при отпускании.
 */
class PullScrollView extends ScrollView {
    interface Listener {
        /** Доля натяжения: 0 - не тянут, 1 - порог достигнут. */
        void onPull(float fraction);
        void onRefresh();
    }

    private Listener listener;
    private final float slop, trigger, maxPull;
    private float downY;
    private boolean pulling, ready;

    PullScrollView(Context c) {
        super(c);
        float d = c.getResources().getDisplayMetrics().density;
        slop = ViewConfiguration.get(c).getScaledTouchSlop();
        trigger = d * 72;       // смещение содержимого, при котором срабатывает обновление
        maxPull = d * 120;
    }

    void setListener(Listener l) { listener = l; }

    private View content() { return getChildAt(0); }

    private float offset(float dy) {
        // затухание: палец уходит дальше, чем содержимое
        float x = Math.max(0f, dy) * 0.5f;
        return Math.min(maxPull, x);
    }

    @Override
    public boolean onInterceptTouchEvent(MotionEvent e) {
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                downY = e.getY();
                pulling = false;
                ready = false;
                break;
            case MotionEvent.ACTION_MOVE:
                if (!pulling && listener != null && getScrollY() == 0 && e.getY() - downY > slop * 2) {
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
        int a = e.getActionMasked();
        if (a == MotionEvent.ACTION_DOWN) {
            downY = e.getY();
            pulling = ready = false;
        }
        // ScrollView мог уже перехватить прокрутку, тогда onIntercept для MOVE не зовётся: условие проверяем и здесь.
        if (!pulling && listener != null && a == MotionEvent.ACTION_MOVE && getScrollY() == 0 && e.getY() - downY > slop * 2) pulling = true;
        if (!pulling) return super.onTouchEvent(e);
        View c = content();
        float off = offset(e.getY() - downY);
        switch (a) {
            case MotionEvent.ACTION_MOVE:
                if (c != null) c.setTranslationY(off);
                boolean now = off >= trigger;
                if (now && !ready) Ui.tick(this);
                ready = now;
                listener.onPull(off / trigger);
                break;
            case MotionEvent.ACTION_UP:
                pulling = false;
                release(c);
                if (ready) { Ui.click(this); listener.onRefresh(); }
                ready = false;
                break;
            case MotionEvent.ACTION_CANCEL:
                pulling = false;
                ready = false;
                release(c);
                break;
            default:
                break;
        }
        return true;
    }

    private void release(View c) {
        listener.onPull(0f);
        if (c != null) c.animate().translationY(0).setDuration(180).start();
    }
}
