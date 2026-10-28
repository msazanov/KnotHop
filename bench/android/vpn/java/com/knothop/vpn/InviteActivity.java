package com.knothop.vpn;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Приглашение v4 (ADR 0019) в три страницы: 1) ноды, которые выдадут права (1-8; где у вас права администратора; по умолчанию ничего не выбрано, одна галочка «все»),
 * 2) права (USE, TRANSIT, EXIT; по умолчанию пресет «Пользователь»), 3) готовое приглашение: QR и строка. Приглашение действует 48 часов.
 * Подтверждение выпуска — обычное подтверждение в интерфейсе; системная биометрия не используется. При выходе (назад, смена приложения)
 * строка и картинка стираются с экрана; приватная очередь хранит pin до подтверждений нод или TTL. Экран закрыт FLAG_SECURE, pin в журнал не пишется.
 * QR создаётся после локального сохранения разрешения. Закрытая очередь LXMF доставляет его нодам асинхронно.
 */
public final class InviteActivity extends Activity {
    private static final String[] R_NAME = {"use", "transit", "exit"};
    private static final String[] R_TEXT = {
        "USE — пользоваться сетью",
        "TRANSIT — пропускать чужой трафик",
        "EXIT — быть выходом в интернет"};
    private static final boolean[] P_USER = {true, false, false};
    private static final boolean[] P_SERVER = {true, true, true};

    private LinearLayout box;
    private int page;
    private boolean sharing, busy;
    private boolean resumed;

    private final List<String[]> nodes = new ArrayList<>();   // {hash, подпись}
    private final List<CheckBox> nodeBoxes = new ArrayList<>();
    private final boolean[] rights = P_USER.clone();
    private final List<String> chosen = new ArrayList<>();

    private String invite;
    private Bitmap qr;
    private ImageView qrView;
    private TextView inviteText;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        ScrollView sv = new ScrollView(this);
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(24, 48, 24, 24);
        sv.addView(box);
        setContentView(sv);
        loadNodes();
        show1();
    }

    /** Ноды, у которых в моём собственном корне есть ADD (поле adm статуса). Статус пишет работающий клиент, поэтому нужно быть подключённым. */
    private void loadNodes() {
        nodes.clear();
        String p = KnotHopVpnService.phase;
        if ("idle".equals(p) || "error".equals(p)) return;
        try {
            JSONArray ex = new JSONObject(Util.read(new File(new File(getFilesDir(), "state"), "status.json"))).optJSONArray("exits");
            for (int i = 0; ex != null && i < ex.length(); i++) {
                JSONObject e = ex.optJSONObject(i);
                String id = e.optString("id", "");
                if (!e.optBoolean("adm") || !id.matches("[0-9a-f]{32}")) continue;
                boolean seen = e.optBoolean("v") || "up".equals(e.optString("s")) || "current".equals(e.optString("s"));
                nodes.add(new String[]{id, TopologyView.shortName(e.optString("n")) + (seen ? "" : "  (не виден)")});
            }
        } catch (Throwable ignored) { }
    }

    private TextView text(String s, int size, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(size);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setPadding(0, 8, 0, 8);
        return t;
    }

    private Button button(String s, View.OnClickListener l) {
        Button x = new Button(this);
        x.setText(s);
        x.setOnClickListener(v -> { Ui.tick(v); l.onClick(v); });
        x.setFilterTouchesWhenObscured(true);   // F8: нажатие не проходит через перекрывающее окно
        return x;
    }

    // ---------------------------------------------------------------- страница 1: ноды

    private void show1() {
        page = 1;
        box.removeAllViews();
        nodeBoxes.clear();
        box.addView(text("Пригласить: шаг 1 из 2", 20, true));
        if (nodes.isEmpty()) {
            box.addView(text("Пока нет доступных нод с правом выпуска приглашений. Для выпуска достаточно режима «Сеть» — включать VPN не требуется.", 14, false));
            box.addView(text("Если это новая собственная сеть, сначала привяжите корень этого телефона к своей серверной ноде (команда knothopd trust-anchor на сервере). "
                    + "Название телефона не зачисляет серверы в сеть и не даёт прав в чужой сети. Публичные RNS-узлы не заменяют ваш VPN-выход.", 14, false));
            if ("idle".equals(KnotHopVpnService.phase) || ("error".equals(KnotHopVpnService.phase) && !KnotHopVpnService.tunHeld)) {
                box.addView(button("Включить сеть без VPN", v -> {
                    try {
                        startForegroundService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_MODE)
                                .putExtra(KnotHopVpnService.EXTRA_MODE, 1));
                        android.widget.Toast.makeText(this, "Запускаю узел. Затем обновите список нод", android.widget.Toast.LENGTH_LONG).show();
                    } catch (RuntimeException e) {
                        android.widget.Toast.makeText(this, "Не удалось запустить узел: " + e.getMessage(), android.widget.Toast.LENGTH_LONG).show();
                    }
                }));
            }
            box.addView(button("Обновить список", v -> { loadNodes(); show1(); }));
            box.addView(button("Назад", v -> finish()));
            return;
        } else {
            box.addView(text("Выберите ноды (от 1 до 8): каждая из них сама выдаст приглашённому права. К остальным он обращаться не будет.", 14, false));
            CheckBox all = new CheckBox(this);
            all.setText("Выбрать все");
            box.addView(all);
            final boolean[] bulk = {false};
            for (String[] n : nodes) {
                CheckBox c = new CheckBox(this);
                c.setText(n[1]);
                c.setTag(n[0]);
                c.setOnCheckedChangeListener((v, on) -> {
                    if (bulk[0]) return;
                    boolean every = true;
                    for (CheckBox x : nodeBoxes) every &= x.isChecked();
                    bulk[0] = true;
                    all.setChecked(every);
                    bulk[0] = false;
                });
                nodeBoxes.add(c);
                box.addView(c);
            }
            all.setOnCheckedChangeListener((v, on) -> {
                if (bulk[0]) return;
                bulk[0] = true;
                for (CheckBox x : nodeBoxes) x.setChecked(on);
                bulk[0] = false;
            });
        }
        box.addView(button("Далее", v -> {
            chosen.clear();
            for (CheckBox c : nodeBoxes) if (c.isChecked()) chosen.add((String) c.getTag());
            if (chosen.isEmpty()) {
                android.widget.Toast.makeText(this, "Отметьте хотя бы одну ноду", android.widget.Toast.LENGTH_SHORT).show();
                return;
            }
            if (chosen.size() > 8) {
                android.widget.Toast.makeText(this, "В приглашение помещается не больше 8 нод", android.widget.Toast.LENGTH_SHORT).show();
                return;
            }
            show2();
        }));
    }

    // ---------------------------------------------------------------- страница 2: права

    private void show2() {
        page = 2;
        box.removeAllViews();
        box.addView(text("Пригласить: шаг 2 из 2", 20, true));
        box.addView(text("Права приглашённого. По умолчанию — обычный пользователь: только пользоваться выходом. Право приглашать и менять настройки по приглашению не выдаётся.", 14, false));
        RadioGroup g = new RadioGroup(this);
        RadioButton rUser = radio("Пользователь (только выход)");
        RadioButton rServer = radio("Сервер (выход и транзит)");
        RadioButton rCustom = radio("Свой набор");
        g.addView(rUser);
        g.addView(rServer);
        g.addView(rCustom);
        box.addView(g);
        final CheckBox[] cb = new CheckBox[R_NAME.length];
        final boolean[] bulk = {false};
        for (int i = 0; i < R_NAME.length; i++) {
            final int k = i;
            cb[i] = new CheckBox(this);
            cb[i].setText(R_TEXT[i]);
            cb[i].setOnCheckedChangeListener((v, on) -> {
                if (bulk[0]) return;
                rights[k] = on;
                g.check(rCustom.getId());
            });
            box.addView(cb[i]);
        }
        g.setOnCheckedChangeListener((grp, id) -> {
            boolean[] src = id == rUser.getId() ? P_USER : id == rServer.getId() ? P_SERVER : null;
            if (src == null) return;
            bulk[0] = true;
            for (int i = 0; i < cb.length; i++) { rights[i] = src[i]; cb[i].setChecked(src[i]); }
            bulk[0] = false;
        });
        g.check(rUser.getId());
        TextView warn = text("Выдать можно только те права, что есть у вас. Приглашение одноразовое и действует 48 часов.", 12, false);
        box.addView(warn);
        box.addView(button("Создать приглашение", v -> {
            if (busy) return;
            if (rightsText().isEmpty()) {
                android.widget.Toast.makeText(this, "Выберите хотя бы одно право", android.widget.Toast.LENGTH_SHORT).show();
                return;
            }
            create();
        }));
        box.addView(button("Назад", v -> show1()));
    }

    private RadioButton radio(String s) {
        RadioButton r = new RadioButton(this);
        r.setText(s);
        r.setId(View.generateViewId());
        return r;
    }

    private String rightsText() {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < R_NAME.length; i++) if (rights[i]) s.append(s.length() == 0 ? "" : "+").append(R_NAME[i]);
        return s.toString();
    }

    // ---------------------------------------------------------------- выпуск и страница 3

    // Корень сети - свой: приглашение выпускает администратор своей сети.
    private void create() {
        busy = true;
        box.removeAllViews();
        box.addView(text("Создаю приглашение…", 16, false));
        final String r = rightsText();
        final String nodeArg = String.join(",", chosen);
        new Thread(() -> {
            File st = new File(getFilesDir(), "state");
            st.mkdirs();
            String sd = st.getAbsolutePath();
            File out = new File(st, "invite_out.txt");
            out.delete();
            int rc = Native.runVpn("whoami --state " + sd, sd);
            if (rc == 0) {
                rc = Native.runVpn("invite --state " + sd + " --rights " + r
                        + " --nodes " + nodeArg + " --out " + out.getAbsolutePath(), sd);
            }
            final String res = rc == 0 ? Util.read(out).trim() : "ошибка: " + Util.read(new File(st, "error.txt"));
            out.delete();
            runOnUiThread(() -> {
                busy = false;
                if (isFinishing() || isDestroyed()) return;
                if (!resumed) { wipe(); finish(); return; }
                if (res.startsWith("kh-")) show3(res); else showError(res);
            });
        }, "knothop-invite").start();
    }

    private void showError(String msg) {
        page = 2;
        box.removeAllViews();
        box.addView(text(msg, 14, false));
        box.addView(button("Назад", v -> show2()));
    }

    private void show3(String inv) {
        page = 3;
        invite = inv;
        box.removeAllViews();
        box.addView(text("Приглашение готово · разрешения в очереди доставки", 20, true));
        box.addView(text("Отсканируйте QR камерой второго телефона (кнопка «Сканировать QR» в приложении) или отправьте строку. "
                + "Приглашение одноразовое, действует 48 часов; новичок увидит права и срок и должен согласиться. "
                + "Ноды могут ещё ожидать разрешение: новичок повторит попытку автоматически. Оставьте режим «Сеть» включённым для отправки; после перезапуска очередь продолжит доставку. "
                + "При выходе QR исчезнет с экрана. Секрет временно хранится только в закрытой очереди доставки; срок действия приглашения — 48 часов.", 13, false));
        qrView = new ImageView(this);
        qrView.setAdjustViewBounds(true);
        try {
            // v4: от 59 (1 нода) до 208 (8 нод) символов; при 900 px ZXing берёт версию QR сам
            qr = renderQr(Profile.LINK + inv.substring(3), 900);
            qrView.setImageBitmap(qr);
        } catch (Throwable e) {
            box.addView(text("QR не получился: " + e.getMessage(), 13, false));
        }
        box.addView(qrView, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        inviteText = text(inv, 10, false);
        inviteText.setTypeface(Typeface.MONOSPACE);
        box.addView(inviteText);
        box.addView(button("Отправить строку", v -> {
            String cur = invite == null ? "" : invite;
            Intent send = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, cur);
            sharing = true;
            startActivity(Intent.createChooser(send, "Отправить приглашение"));
        }));
        box.addView(button("Готово", v -> finish()));
    }

    private static Bitmap renderQr(String content, int size) throws Exception {
        Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        hints.put(EncodeHintType.MARGIN, 2);
        hints.put(EncodeHintType.CHARACTER_SET, "ISO-8859-1");
        BitMatrix m = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size, hints);
        int w = m.getWidth(), h = m.getHeight();
        int[] px = new int[w * h];
        for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) px[y * w + x] = m.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
        return Bitmap.createBitmap(px, w, h, Bitmap.Config.ARGB_8888);
    }

    /** Стереть приглашение из памяти экрана. */
    private void wipe() {
        invite = null;
        if (inviteText != null) inviteText.setText("");
        if (qrView != null) qrView.setImageBitmap(null);
        if (qr != null) { qr.recycle(); qr = null; }
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        sharing = false;
    }

    @Override
    protected void onPause() {
        resumed = false;
        super.onPause();
    }

    @Override
    protected void onStop() {
        super.onStop();
        // ушли с экрана (кроме системного меню «Отправить»): приглашение стирается, раздел закрывается
        if ((page == 3 || busy) && !sharing && !isChangingConfigurations()) {
            wipe();
            finish();
        }
    }

    @Override
    public void onBackPressed() {
        if (busy) return;
        if (page == 2) show1();
        else finish();
    }

    @Override
    protected void onDestroy() {
        wipe();
        super.onDestroy();
    }

}
