package com.knothop.vpn;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
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
import java.text.DateFormat;
import java.util.Date;
import java.util.EnumMap;
import java.util.Map;

/**
 * Код сервера (ADR 0027): телефон-админ создаёт один код от собственного корня, серверы вступают в сеть сами
 * (`knothopd node --invite-file`), получая от корня подписанные права. Код — секрет: экран закрыт FLAG_SECURE,
 * при уходе с экрана строка и QR стираются, повторный показ идёт из закрытого файла состояния (0600).
 * Запросы серверов принимает работающий узел телефона, поэтому режим «Сеть» должен быть включён, пока серверы вступают.
 */
public final class ServerInviteActivity extends Activity {
    private static final int[] SLOTS = {4, 8, 16, 32};

    private LinearLayout box;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean resumed, sharing, busy;
    private String code, codeId;
    private Bitmap qr;
    private ImageView qrView;
    private TextView codeText, statusText;
    private boolean useTransit = true, useExit = true, useAdd = true, useUse = false;
    private int slots = 16;
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (!resumed || isFinishing() || isDestroyed()) return;
            refreshStatus();
            ui.postDelayed(this, 4000);
        }
    };

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
        showHome();
    }

    private File stateDir() {
        File st = new File(getFilesDir(), "state");
        st.mkdirs();
        return st;
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
        x.setFilterTouchesWhenObscured(true);
        return x;
    }

    /** Узел телефона принимает запросы серверов только когда работает. Включаем «Сеть без VPN», если он остановлен. */
    private void ensureNetwork() {
        String p = KnotHopVpnService.phase;
        if ("idle".equals(p) || ("error".equals(p) && !KnotHopVpnService.tunHeld)) {
            try {
                startForegroundService(new Intent(this, KnotHopVpnService.class).setAction(KnotHopVpnService.A_MODE)
                        .putExtra(KnotHopVpnService.EXTRA_MODE, 1));
            } catch (RuntimeException e) {
                android.widget.Toast.makeText(this, "Не удалось запустить узел: " + e.getMessage(), android.widget.Toast.LENGTH_LONG).show();
            }
        }
    }

    // ---------------------------------------------------------------- главная: форма и список кодов

    private void showHome() {
        codeId = null;
        wipe();
        box.removeAllViews();
        box.addView(text("Серверы по коду", 20, true));
        box.addView(text("Создайте один код и разверните по нему свои серверы: каждый сервер сам вступит в вашу сеть и получит права, "
                + "которые вы выберете ниже. Ключ корня сети — на этом телефоне; на серверах вручную ничего привязывать не нужно. "
                + "Код действует 48 часов и может использоваться несколькими серверами (до выбранного числа).", 14, false));
        CheckBox cTransit = check("TRANSIT — пропускать трафик между серверами", useTransit);
        CheckBox cExit = check("EXIT — быть выходом в интернет", useExit);
        CheckBox cAdd = check("ADD — выпускать приглашения клиентам (kh-), права не шире своих", useAdd);
        CheckBox cUse = check("USE — пользоваться сетью как клиент", useUse);
        cTransit.setOnCheckedChangeListener((v, on) -> useTransit = on);
        cExit.setOnCheckedChangeListener((v, on) -> useExit = on);
        cAdd.setOnCheckedChangeListener((v, on) -> useAdd = on);
        cUse.setOnCheckedChangeListener((v, on) -> useUse = on);
        box.addView(cTransit);
        box.addView(cExit);
        box.addView(cAdd);
        box.addView(cUse);
        box.addView(text("Сколько серверов могут вступить по коду:", 14, false));
        RadioGroup g = new RadioGroup(this);
        g.setOrientation(RadioGroup.HORIZONTAL);
        for (int n : SLOTS) {
            RadioButton r = new RadioButton(this);
            r.setText(String.valueOf(n));
            r.setId(View.generateViewId());
            r.setTag(n);
            g.addView(r);
            if (n == slots) r.setChecked(true);
        }
        g.setOnCheckedChangeListener((grp, id) -> {
            View r = grp.findViewById(id);
            if (r != null && r.getTag() instanceof Integer) slots = (Integer) r.getTag();
        });
        box.addView(g);
        box.addView(text("Права REMOVE и CONFIG кодом не выдаются. С правом ADD сервер можно выбрать входной нодой приглашения пользователей (kh-); новый пользователь получает только USE.", 12, false));
        box.addView(button("Создать код сервера", v -> {
            if (busy) return;
            if (rightsText().isEmpty()) {
                android.widget.Toast.makeText(this, "Выберите хотя бы одно право", android.widget.Toast.LENGTH_SHORT).show();
                return;
            }
            create();
        }));
        box.addView(button("Назад", v -> finish()));
        box.addView(text("Мои коды", 16, true));
        TextView list = text("Загружаю…", 13, false);
        box.addView(list);
        new Thread(() -> {
            String sd = stateDir().getAbsolutePath();
            JSONArray codes = readCodes(sd);
            runOnUiThread(() -> { if (!isFinishing() && !isDestroyed()) fillList(list, codes); });
        }, "knothop-server-codes").start();
    }

    private CheckBox check(String s, boolean on) {
        CheckBox c = new CheckBox(this);
        c.setText(s);
        c.setChecked(on);
        return c;
    }

    private String rightsText() {
        StringBuilder s = new StringBuilder();
        if (useUse) s.append("use");
        if (useTransit) s.append(s.length() == 0 ? "" : "+").append("transit");
        if (useExit) s.append(s.length() == 0 ? "" : "+").append("exit");
        if (useAdd) s.append(s.length() == 0 ? "" : "+").append("add");
        return s.toString();
    }

    private JSONArray readCodes(String sd) {
        try {
            JSONObject o = new JSONObject(Native.runCLI("server-invites --state " + sd, sd));
            JSONArray a = o.optJSONArray("codes");
            return a == null ? new JSONArray() : a;
        } catch (Throwable e) {
            return new JSONArray();
        }
    }

    private void fillList(TextView placeholder, JSONArray codes) {
        int at = box.indexOfChild(placeholder);
        box.removeView(placeholder);
        if (codes.length() == 0) {
            box.addView(text("Пока нет ни одного кода.", 13, false), at);
            return;
        }
        DateFormat df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);
        for (int i = 0; i < codes.length(); i++) {
            JSONObject c = codes.optJSONObject(i);
            if (c == null) continue;
            final String id = c.optString("id", "");
            String st = c.optString("state", "");
            String stRu = "active".equals(st) ? "действует" : "full".equals(st) ? "все места заняты" : "revoked".equals(st) ? "отозван" : "истёк";
            StringBuilder sb = new StringBuilder();
            sb.append(stRu).append(" · вступило ").append(c.optInt("joined")).append(" из ").append(c.optInt("max"))
              .append(" · ").append(c.optString("rights_text"))
              .append("\nдо ").append(df.format(new Date(c.optLong("expires") * 1000)));
            JSONArray sv = c.optJSONArray("servers");
            for (int k = 0; sv != null && k < sv.length(); k++) {
                JSONObject s = sv.optJSONObject(k);
                if (s == null) continue;
                String nm = s.optString("name", "");
                sb.append("\n  • ").append(nm.isEmpty() ? s.optString("hash", "").substring(0, 8) : nm);
            }
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(0, 12, 0, 12);
            row.addView(text(sb.toString(), 13, false));
            if ("active".equals(st) || "full".equals(st)) {
                LinearLayout btns = new LinearLayout(this);
                btns.setOrientation(LinearLayout.HORIZONTAL);
                if ("active".equals(st)) btns.addView(button("Показать код", v -> show(id)));
                btns.addView(button("Отозвать", v -> revoke(id)));
                row.addView(btns);
            }
            box.addView(row, at + i);
        }
    }

    // ---------------------------------------------------------------- создание, показ, отзыв

    private void create() {
        busy = true;
        ensureNetwork();
        box.removeAllViews();
        box.addView(text("Создаю код…", 16, false));
        final String r = rightsText();
        final int n = slots;
        new Thread(() -> {
            File st = stateDir();
            String sd = st.getAbsolutePath();
            File out = new File(st, "server_code_out.txt");
            out.delete();
            int rc = Native.runVpn("whoami --state " + sd, sd);
            if (rc == 0) rc = Native.runVpn("invite-server --state " + sd + " --rights " + r + " --max " + n + " --out " + out.getAbsolutePath(), sd);
            final String res = rc == 0 ? Util.read(out).trim() : "ошибка: " + Util.read(new File(st, "error.txt"));
            out.delete();
            final JSONArray codes = rc == 0 ? readCodes(sd) : new JSONArray();
            runOnUiThread(() -> {
                busy = false;
                if (isFinishing() || isDestroyed()) return;
                if (!resumed) { wipe(); finish(); return; }
                if (res.startsWith("khs-")) {
                    JSONObject first = codes.optJSONObject(0);
                    showCode(res, first == null ? null : first.optString("id", null));
                } else {
                    box.removeAllViews();
                    box.addView(text(res, 14, false));
                    box.addView(button("Назад", v -> showHome()));
                }
            });
        }, "knothop-server-code").start();
    }

    private void show(String id) {
        if (busy) return;
        busy = true;
        new Thread(() -> {
            File st = stateDir();
            String sd = st.getAbsolutePath();
            File out = new File(st, "server_code_out.txt");
            out.delete();
            int rc = Native.runVpn("server-invites --state " + sd + " --show " + id + " --out " + out.getAbsolutePath(), sd);
            final String res = rc == 0 ? Util.read(out).trim() : "";
            out.delete();
            runOnUiThread(() -> {
                busy = false;
                if (isFinishing() || isDestroyed() || !resumed) return;
                if (res.startsWith("khs-")) showCode(res, id);
            });
        }, "knothop-server-code-show").start();
    }

    private void revoke(String id) {
        new Thread(() -> {
            String sd = stateDir().getAbsolutePath();
            Native.runCLI("server-invites --state " + sd + " --revoke " + id, sd);
            runOnUiThread(() -> { if (!isFinishing() && !isDestroyed()) showHome(); });
        }, "knothop-server-code-revoke").start();
    }

    private void showCode(String c, String id) {
        code = c;
        codeId = id;
        box.removeAllViews();
        box.addView(text("Код сервера готов", 20, true));
        box.addView(text("На каждом сервере: 1) сохраните код в файл с правами 0600, например /opt/knothop/server.code; "
                + "2) в node.json укажите \"invite_file\": \"/opt/knothop/server.code\" (или запустите knothopd node --invite-file ФАЙЛ); "
                + "3) запустите knothopd. Сервер сам привяжет ваш корень, запросит права и вступит в сеть; после вступления файл кода удаляется. "
                + "Один код подходит для всех ваших серверов (в пределах выбранного числа).", 13, false));
        box.addView(text("Пока серверы вступают, держите на телефоне режим «Сеть» включённым: запросы принимает этот телефон. "
                + "Код — секрет: любой, у кого он есть, может добавить сервер в вашу сеть до истечения срока. Не публикуйте его; при утечке отзовите код.", 13, false));
        qrView = new ImageView(this);
        qrView.setAdjustViewBounds(true);
        try {
            qr = renderQr(c, 900);
            qrView.setImageBitmap(qr);
        } catch (Throwable e) {
            box.addView(text("QR не получился: " + e.getMessage(), 13, false));
        }
        box.addView(qrView, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        codeText = text(c, 10, false);
        codeText.setTypeface(Typeface.MONOSPACE);
        codeText.setTextIsSelectable(false);
        box.addView(codeText);
        box.addView(button("Копировать", v -> copy()));
        box.addView(button("Отправить строку", v -> {
            sharing = true;
            startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_TEXT, code == null ? "" : code), "Отправить код сервера"));
        }));
        statusText = text("Вступило: 0", 14, true);
        box.addView(statusText);
        box.addView(button("Отозвать код", v -> { if (codeId != null) revoke(codeId); }));
        box.addView(button("Готово", v -> showHome()));
        refreshStatus();
    }

    private void copy() {
        if (code == null) return;
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData cd = ClipData.newPlainText("KnotHop", code);
        if (Build.VERSION.SDK_INT >= 33) {
            android.os.PersistableBundle pb = new android.os.PersistableBundle();
            pb.putBoolean("android.content.extra.IS_SENSITIVE", true);
            cd.getDescription().setExtras(pb);
        }
        cm.setPrimaryClip(cd);
        android.widget.Toast.makeText(this, "Скопировано. Вставьте в файл на сервере и очистите буфер обмена", android.widget.Toast.LENGTH_LONG).show();
    }

    private void refreshStatus() {
        if (statusText == null || codeId == null) return;
        final String id = codeId;
        new Thread(() -> {
            JSONArray codes = readCodes(stateDir().getAbsolutePath());
            String line = null;
            for (int i = 0; i < codes.length(); i++) {
                JSONObject c = codes.optJSONObject(i);
                if (c == null || !id.equals(c.optString("id"))) continue;
                StringBuilder sb = new StringBuilder("Вступило: " + c.optInt("joined") + " из " + c.optInt("max"));
                if ("revoked".equals(c.optString("state"))) sb.append(" (код отозван)");
                JSONArray sv = c.optJSONArray("servers");
                for (int k = 0; sv != null && k < sv.length(); k++) {
                    JSONObject s = sv.optJSONObject(k);
                    if (s == null) continue;
                    String nm = s.optString("name", "");
                    sb.append("\n  • ").append(nm.isEmpty() ? s.optString("hash", "").substring(0, 8) : nm);
                }
                line = sb.toString();
            }
            final String shown = line;
            runOnUiThread(() -> { if (shown != null && statusText != null && id.equals(codeId)) statusText.setText(shown); });
        }, "knothop-server-code-status").start();
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

    /** Стереть код из памяти экрана. */
    private void wipe() {
        code = null;
        if (codeText != null) codeText.setText("");
        if (qrView != null) qrView.setImageBitmap(null);
        if (qr != null) { qr.recycle(); qr = null; }
        codeText = null;
        qrView = null;
        statusText = null;
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        sharing = false;
        ui.postDelayed(poll, 4000);
    }

    @Override
    protected void onPause() {
        resumed = false;
        ui.removeCallbacks(poll);
        super.onPause();
    }

    @Override
    protected void onStop() {
        super.onStop();
        // ушли с экрана (кроме системного меню «Отправить»): код стирается, раздел закрывается
        if ((code != null || busy) && !sharing && !isChangingConfigurations()) {
            wipe();
            finish();
        }
    }

    @Override
    public void onBackPressed() {
        if (busy) return;
        if (code != null) showHome();
        else finish();
    }

    @Override
    protected void onDestroy() {
        wipe();
        super.onDestroy();
    }
}
