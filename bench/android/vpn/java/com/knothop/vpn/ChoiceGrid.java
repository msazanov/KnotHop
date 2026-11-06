package com.knothop.vpn;

import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Выбор одного варианта кнопками-плитками в сетке {@code cols} столбцов (вместо горизонтального RadioGroup, который на узком экране
 * сжимает подписи и переносит текст по буквам). Плитка занимает равную долю ширины, текст переносится по словам.
 */
final class ChoiceGrid extends LinearLayout {
    interface Listener { void onChoice(int index, boolean fromUser); }

    private final TextView[] tiles;
    private int checked = -1;
    private Listener listener;

    ChoiceGrid(Context c, String[] labels, int cols) {
        super(c);
        setOrientation(VERTICAL);
        tiles = new TextView[labels.length];
        int[][] rows = layout(labels.length, cols);
        int gap = Ui.dp(c, 6);
        for (int r = 0; r < rows.length; r++) {
            LinearLayout row = new LinearLayout(c);
            row.setOrientation(HORIZONTAL);
            for (int k = 0; k < cols; k++) {
                LayoutParams lp = new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f);
                lp.rightMargin = k + 1 < cols ? gap : 0;
                if (k < rows[r].length) {
                    final int idx = rows[r][k];
                    TextView t = new TextView(c);
                    t.setText(labels[idx]);
                    t.setTextSize(13);
                    t.setGravity(Gravity.CENTER);
                    t.setMinHeight(Ui.dp(c, 44));
                    t.setPadding(Ui.dp(c, 8), Ui.dp(c, 6), Ui.dp(c, 8), Ui.dp(c, 6));
                    t.setClickable(true);
                    t.setOnClickListener(v -> { Ui.tick(v); select(idx, true); });
                    tiles[idx] = t;
                    row.addView(t, lp);
                } else {
                    row.addView(new View(c), lp);   // пустая ячейка последней строки держит ширину столбца
                }
            }
            LayoutParams rp = new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT);
            rp.topMargin = r == 0 ? 0 : gap;
            addView(row, rp);
        }
        paint();
    }

    /** Разбивка n плиток по строкам из {@code cols} столбцов: индексы плиток каждой строки. */
    static int[][] layout(int n, int cols) {
        int rowsN = (n + cols - 1) / cols;
        int[][] rows = new int[rowsN][];
        for (int r = 0; r < rowsN; r++) {
            int len = Math.min(cols, n - r * cols);
            rows[r] = new int[len];
            for (int k = 0; k < len; k++) rows[r][k] = r * cols + k;
        }
        return rows;
    }

    void setListener(Listener l) { listener = l; }

    int checked() { return checked; }

    /** Выбрать плитку программно (без отклика пользователю). */
    void select(int i) { select(i, false); }

    private void select(int i, boolean user) {
        checked = i;
        paint();
        if (listener != null) listener.onChoice(i, user);
    }

    private void paint() {
        Context c = getContext();
        for (int i = 0; i < tiles.length; i++) {
            boolean on = i == checked;
            tiles[i].setBackground(on ? Ui.round(Ui.ORANGE, 12, c) : Ui.roundStroke(Ui.CARD_HI, Ui.STROKE, 12, c));
            tiles[i].setTextColor(on ? Ui.ON_ACCENT : Ui.TEXT);
        }
    }
}
