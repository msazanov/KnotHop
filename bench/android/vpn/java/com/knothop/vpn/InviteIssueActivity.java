package com.knothop.vpn;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.WindowManager;
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

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Один экран выпуска приглашения (ADR 0028 §2.2-2.5). «Сервер / Пользователь / Админ / Свои» - только пресеты: они заполняют флажки прав
 * в спойлере «Права ▸» (права получателя на выбранных нодах и управление получателем для выдавшего), ручная правка переключает на «Свои».
 * Логика выпуска одна: стопка пар по выбранным нодам, у каждой нода свой пин. Первой всегда идёт «Этот телефон» (любая нода сама себе админ:
 * приглашение выпускается без других узлов, пара своей ноды применяется сразу, остальным уходит команда «ожидай»).
 * Права на чужой ноде не выше моих на ней: подсказка здесь, отказ - на ноде. Экран закрыт FLAG_SECURE; строка и QR стираются при уходе с экрана.
 */
public final class InviteIssueActivity extends Activity {
    private static final int[] TTL_H = {6, 24, 48, 168};
    private static final String[] TTL_NAMES = {"6 часов", "сутки", "48 часов", "7 суток"};
    private LinearLayout box, nodeBox, rightsBody, resultBox;
    private RadioGroup preset, ttl;
    private CheckBox[] rightBoxes, mgmtBoxes;
    private TextView rightsToggle, hintView;
    private boolean filling, rightsOpen;
    private final List<Row> rows = new ArrayList<>();
    private JSONObject view = new JSONObject();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private String invite, me = "";
    private ImageView qrView;
    private TextView inviteText, progress;
    private Bitmap qr;
    private JSONArray requests;
    private boolean sharing, offline;
    private final Runnable poll = new Runnable() {
        @Override public void run() { pollOutbox(); ui.postDelayed(this, 2500); }
    };

    /** Строка списка нод: своя (первая) или нода, которой я управляю. */
    private static final class Row {
        String hash, label;
        boolean self;
        int mine = -1;          // мои права на ноде по её статусу, -1 - неизвестны
        CheckBox cb;
    }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Ui.BG);
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(Ui.dp(this, 16), Ui.dp(this, 20), Ui.dp(this, 16), Ui.dp(this, 24));
        scroll.addView(box);
        setContentView(scroll);
        box.addView(Ui.titleWithHelp(this, "Приглашение",
                "Приглашение — одноразовая строка из пар «хеш ноды + пин»; в ней нет ни прав, ни ключей. Права назначаете вы здесь, а нода применит их при погашении. "
                + "Срок — до 7 суток (по умолчанию 48 часов). Строку передавайте только доверенным каналом: пока она не погашена, любой её обладатель получит эти права."));
        LinearLayout kind = Ui.card(this);
        kind.addView(Ui.titleWithHelp(this, "Пресет", "Пресет только выставляет права ниже и больше ничего не меняет. «Сервер»: новая нода, этот телефон становится её админом. "
                + "«Пользователь»: USE на выбранных нодах (выход в интернет — свойство самой ноды). «Админ»: CONFIG, ADD, REMOVE и USE. «Свои»: любые права вручную."));
        preset = new RadioGroup(this);
        preset.setOrientation(RadioGroup.HORIZONTAL);
        for (int i = 0; i < Rights.PRESET_NAMES.length; i++) {
            RadioButton r = new RadioButton(this);
            r.setId(100 + i);
            r.setText(Rights.PRESET_NAMES[i]);
            r.setTextColor(Ui.TEXT);
            r.setTextSize(12);
            preset.addView(r);
        }
        preset.setOnCheckedChangeListener((g, id) -> { if (!filling && id >= 100 && id != 100 + Rights.P_CUSTOM) applyPreset(id - 100); });
        kind.addView(preset);
        box.addView(kind, Ui.cardParams(this));
        buildRights();
        nodeBox = Ui.card(this);
        box.addView(nodeBox, Ui.cardParams(this));
        LinearLayout t = Ui.card(this);
        t.addView(Ui.title(this, "Срок"));
        ttl = new RadioGroup(this);
        ttl.setOrientation(RadioGroup.HORIZONTAL);
        for (int i = 0; i < TTL_H.length; i++) {
            RadioButton r = new RadioButton(this);
            r.setId(200 + i);
            r.setText(TTL_NAMES[i]);
            r.setTextColor(Ui.TEXT);
            r.setTextSize(12);
            ttl.addView(r);
        }
        ttl.check(202);
        t.addView(ttl);
        box.addView(t, Ui.cardParams(this));
        hintView = Ui.text(this, "", 12, Ui.ORANGE, false);
        box.addView(hintView);
        box.addView(Ui.primary(this, "Выпустить", v -> issue()), Ui.cardParams(this));
        resultBox = new LinearLayout(this);
        resultBox.setOrientation(LinearLayout.VERTICAL);
        box.addView(resultBox);
        applyPreset(Rights.P_USER);
        renderNodes();
        loadNodes();
    }

    /** Спойлер «Права ▸»: флажки прав получателя и управления получателем; заполняет пресет, ручная правка переключает на «Свои». */
    private void buildRights() {
        LinearLayout card = Ui.card(this);
        rightsToggle = Ui.text(this, "", 15, Ui.TEXT, true);
        rightsToggle.setOnClickListener(v -> { rightsOpen = !rightsOpen; Ui.tick(v); updateRights(); });
        card.addView(rightsToggle);
        rightsBody = new LinearLayout(this);
        rightsBody.setOrientation(LinearLayout.VERTICAL);
        rightsBody.addView(Ui.titleWithHelp(this, "Права получателя на выбранных нодах", "Что нода разрешит получателю на себе при погашении. "
                + "На чужой ноде нельзя выдать больше, чем есть у вас на ней (нода откажет). HOST_ACCESS выдаёт только админ ноды (CONFIG)."));
        rightBoxes = new CheckBox[Rights.BITS.length];
        for (int i = 0; i < rightBoxes.length; i++) rightBoxes[i] = rightBox(rightsBody, i);
        rightsBody.addView(Ui.titleWithHelp(this, "Управление получателем", "Что получит выдавший (этот телефон) на ноде получателя: "
                + "для нового сервера — права админа над ним. Применяется к паре «Этот телефон»; у чужих нод управление не запрашивается."));
        mgmtBoxes = new CheckBox[Rights.BITS.length];
        for (int i = 0; i < mgmtBoxes.length; i++) mgmtBoxes[i] = rightBox(rightsBody, i);
        card.addView(rightsBody);
        box.addView(card, Ui.cardParams(this));
        updateRights();
    }

    private CheckBox rightBox(LinearLayout into, int i) {
        CheckBox cb = new CheckBox(this);
        cb.setTextColor(Ui.TEXT);
        cb.setTextSize(13);
        cb.setText(Rights.NAMES[i] + " — " + Rights.HINTS[i]);
        cb.setOnCheckedChangeListener((v, on) -> {
            if (filling) return;
            filling = true;
            preset.check(100 + Rights.P_CUSTOM);   // ручная правка = «Свои»
            filling = false;
            updateRights();
        });
        into.addView(cb);
        return cb;
    }

    private void applyPreset(int p) {
        filling = true;
        preset.check(100 + p);
        int r = Rights.presetRights(p), m = Rights.presetMgmt(p);
        for (int i = 0; i < rightBoxes.length; i++) { rightBoxes[i].setChecked((r & Rights.BITS[i]) != 0); mgmtBoxes[i].setChecked((m & Rights.BITS[i]) != 0); }
        filling = false;
        updateRights();
    }

    private int rightsMask() {
        int r = 0;
        for (int i = 0; i < rightBoxes.length; i++) if (rightBoxes[i].isChecked()) r |= Rights.BITS[i];
        return r;
    }

    private int mgmtMask() {
        int m = 0;
        for (int i = 0; i < mgmtBoxes.length; i++) if (mgmtBoxes[i].isChecked()) m |= Rights.BITS[i];
        return m;
    }

    /** Заголовок спойлера с краткой сводкой, подсказки о правах выше моих на чужих нодах. */
    private void updateRights() {
        if (rightsToggle == null || rightsBody == null) return;
        rightsToggle.setText((rightsOpen ? "Права ▾" : "Права ▸") + "   " + Rights.text(rightsMask()) + (mgmtMask() != 0 ? "  ·  управление: " + Rights.text(mgmtMask()) : ""));
        rightsBody.setVisibility(rightsOpen ? android.view.View.VISIBLE : android.view.View.GONE);
        int r = rightsMask();
        StringBuilder h = new StringBuilder();
        for (Row row : rows) {
            if (row.self || row.cb == null) continue;
            int ex = row.mine < 0 ? 0 : Rights.exceeds(r, row.mine);
            row.cb.setText(row.label + (row.mine < 0 ? "\nмои права там: неизвестны" : "\nмои права там: " + Rights.text(row.mine)) + (ex != 0 ? "\n⚠ выше ваших (" + Rights.text(ex) + "): нода откажет" : ""));
            row.cb.setTextColor(ex != 0 ? Ui.ORANGE : Ui.TEXT);
            if (ex != 0 && row.cb.isChecked()) h.append("На ").append(row.hash.substring(0, 8)).append(" нельзя выдать больше ваших прав: ").append(Rights.text(ex)).append(". ");
        }
        if ((r & Rights.HOST_ACCESS) != 0) h.append("HOST_ACCESS нода примет только от админа (CONFIG). ");
        if (mgmtMask() != 0 && !selfChecked()) h.append("Управление получателем применяется только при выбранном «Этот телефон». ");
        if (hintView != null) hintView.setText(h.toString().trim());
    }

    private boolean selfChecked() {
        for (Row row : rows) if (row.self && row.cb.isChecked()) return true;
        return false;
    }

    private void loadNodes() {
        new Thread(() -> {
            JSONObject v = Ctl.call(this, Ctl.req("view"));
            ui.post(() -> { view = v; renderNodes(); });
        }, "knothop-invite-nodes").start();
    }

    private static String nameOf(JSONArray contacts, String h) {
        for (int i = 0; contacts != null && i < contacts.length(); i++) {
            JSONObject c = contacts.optJSONObject(i);
            if (c != null && h.equals(c.optString("hash")) && !c.optString("name").isEmpty()) return Rights.clip(c.optString("name"));
        }
        return h.substring(0, 8);
    }

    /** Мои права на ноде по её статусу (пары peers); -1 - меня в присланной странице нет. */
    private int myRightsOn(JSONObject status) {
        JSONArray peers = status == null ? null : status.optJSONArray("peers");
        for (int i = 0; peers != null && i < peers.length(); i++) {
            JSONObject p = peers.optJSONObject(i);
            if (p != null && me.equals(p.optString("hash"))) return p.optInt("rights");
        }
        return -1;
    }

    /** Список нод: «Этот телефон» первым и выбран по умолчанию; дальше ноды, где у меня есть ADD/CONFIG. */
    private void renderNodes() {
        java.util.Map<String, Boolean> keep = new java.util.HashMap<>();
        for (Row row : rows) keep.put(row.hash, row.cb.isChecked());
        rows.clear();
        me = view.optString("me", "");
        offline = view.optBoolean("offline") || (!view.optBoolean("ok", true));
        JSONArray contacts = view.optJSONArray("contacts");
        JSONObject managed = view.optJSONObject("nodes");
        Row self = new Row();
        self.self = true;
        self.hash = me.isEmpty() ? "self" : me;
        self.label = "Этот телефон" + (me.isEmpty() ? "" : "  " + me.substring(0, 8)) + "  ·  моя нода";
        rows.add(self);
        for (java.util.Iterator<String> it = managed == null ? new java.util.ArrayList<String>().iterator() : managed.keys(); it.hasNext(); ) {
            String h = it.next();
            JSONObject entry = managed.optJSONObject(h);
            Row r = new Row();
            r.hash = h;
            r.mine = myRightsOn(entry == null ? null : entry.optJSONObject("status"));
            if (r.mine >= 0 && (r.mine & (Rights.ADD | Rights.CONFIG)) == 0) continue;   // ADD/CONFIG нет - приглашение там не выпустить
            r.label = nameOf(contacts, h) + "  " + h.substring(0, 8);
            rows.add(r);
        }
        nodeBox.removeAllViews();
        nodeBox.addView(Ui.titleWithHelp(this, "Где погасить",
                "Приглашение должно быть погашено на каждой из выбранных нод (у каждой свой пин). «Этот телефон» — ваша нода: любая нода сама себе админ, поэтому выпустить "
                + "приглашение можно без других узлов. Остальным нодам, которыми вы управляете, уходит команда «ожидай»; пока нода офлайн, команда ждёт и повторяется. "
                + "Включите все ноды, через которые получатель может ходить (в т.ч. транзитные)."));
        for (Row row : rows) {
            CheckBox cb = new CheckBox(this);
            cb.setTextColor(Ui.TEXT);
            cb.setText(row.label);
            Boolean was = keep.get(row.hash);
            cb.setChecked(row.self ? was == null || was : Boolean.TRUE.equals(was));
            cb.setEnabled(row.self || !offline);
            cb.setOnCheckedChangeListener((v, on) -> updateRights());
            row.cb = cb;
            nodeBox.addView(cb);
        }
        if (offline) nodeBox.addView(Ui.text(this, "«Сеть» выключена: на этом телефоне выпустить можно, но получатель сможет погасить приглашение, только когда вы включите «Сеть». "
                + "Другие ноды доступны, пока «Сеть» включена.", 12, Ui.ORANGE, false));
        updateRights();
    }

    private void issue() {
        long ttlMs = TTL_H[Math.max(0, ttl.getCheckedRadioButtonId() - 200)] * 3600_000L;
        int r = rightsMask(), m = mgmtMask();
        if (r == 0) { resultMsg("Выберите хотя бы одно право получателя."); return; }
        JSONObject req = Ctl.req("issue");
        try {
            req.put("ttl_ms", ttlMs);
            boolean self = selfChecked();
            int foreign = 0;
            for (Row row : rows) if (!row.self && row.cb.isChecked()) foreign++;
            if (!self && foreign == 0) { resultMsg("Выберите хотя бы одну ноду."); return; }
            if (foreign == 0) {
                req.put("rights", r).put("mgmt", m);              // только своя нода: работает и при выключенной «Сети»
            } else {
                if (self && me.isEmpty()) { resultMsg("Хеш этой ноды неизвестен: включите «Сеть» и повторите."); return; }
                JSONArray nodes = new JSONArray();
                if (self) nodes.put(new JSONObject().put("hash", me).put("rights", r).put("mgmt", m));
                for (Row row : rows) if (!row.self && row.cb.isChecked()) nodes.put(new JSONObject().put("hash", row.hash).put("rights", r).put("mgmt", 0));
                req.put("nodes", nodes);
            }
        } catch (Exception e) { resultMsg("Ошибка: " + e.getMessage()); return; }
        resultMsg("Выпускаю…");
        new Thread(() -> {
            JSONObject res = Ctl.call(this, req);
            ui.post(() -> show(res));
        }, "knothop-invite-issue").start();
    }

    private void resultMsg(String s) {
        resultBox.removeAllViews();
        resultBox.addView(Ui.text(this, s, 13, Ui.ORANGE, false));
    }

    private void show(JSONObject r) {
        if (!r.optBoolean("ok")) { resultMsg("Не выпущено: " + r.optString("error", "?")); return; }
        invite = r.optString("invite");
        requests = r.optJSONArray("requests");
        resultBox.removeAllViews();
        LinearLayout card = Ui.card(this);
        card.addView(Ui.titleWithHelp(this, "Приглашение", "Покажите QR или отправьте строку получателю. Строка исчезнет с экрана при уходе отсюда; "
                + "выпущенные приглашения и их состояние видны в разделе «Сеть»."));
        try {
            qr = renderQr(Profile.LINK + invite, Ui.dp(this, 280));
            qrView = new ImageView(this);
            qrView.setImageBitmap(qr);
            card.addView(qrView, new LinearLayout.LayoutParams(-1, -2));
        } catch (Exception e) {
            card.addView(Ui.muted(this, "QR не построен (слишком длинная строка): отправьте текстом."));
        }
        inviteText = Ui.text(this, invite, 10, Ui.TEXT, false);
        inviteText.setTypeface(Typeface.MONOSPACE);
        card.addView(inviteText);
        progress = Ui.muted(this, "");
        card.addView(progress);
        if (r.optBoolean("offline")) {
            // выпуск без запущенной ноды: пин записан в таблицу этого телефона, погасить его можно только при включённой «Сети»
            progress.setText("Приглашение записано на этом телефоне. Включите «Сеть», чтобы получатель мог погасить его.");
            progress.setTextColor(Ui.ORANGE);
        }
        card.addView(Ui.secondary(this, "Отправить строку", v -> {
            sharing = true;
            startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, invite == null ? "" : invite), "Отправить приглашение"));
        }));
        card.addView(Ui.primary(this, "Готово", v -> finish()));
        resultBox.addView(card, Ui.cardParams(this));
        ui.removeCallbacks(poll);
        ui.post(poll);
    }

    private void pollOutbox() {
        if (requests == null || requests.length() == 0 || progress == null) return;
        new Thread(() -> {
            JSONObject v = Ctl.call(this, Ctl.req("view"));
            JSONArray ob = v.optJSONArray("outbox");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < requests.length(); i++) {
                JSONObject q = requests.optJSONObject(i);
                String h = q.optString("hash"), rid = q.optString("requestid"), st = "?", code = "";
                for (int j = 0; ob != null && j < ob.length(); j++) {
                    JSONObject o = ob.optJSONObject(j);
                    if (!rid.equals(o.optString("rid"))) continue;
                    st = o.optString("state");
                    // результат: ответ чужой ноды - массив [{state,code}], своей - {"local":true,"r":[...]}
                    JSONArray rs = o.optJSONArray("results");
                    if (rs == null && o.optJSONObject("results") != null) rs = o.optJSONObject("results").optJSONArray("r");
                    if (rs != null && rs.length() > 0 && rs.optJSONObject(0) != null) code = rs.optJSONObject(0).optString("code", "");
                }
                String who = h.equals(me) ? "этот телефон" : h.substring(0, 8);
                String text = "applied".equals(st) ? "готова" : "pending".equals(st) ? "ожидает уведомления"
                        : "rejected".equals(st) ? "нода отказала" + (code.isEmpty() || "null".equals(code) ? "" : " (" + code + ")" + ("rights_exceed".equals(code) ? ": права выше ваших на ней" : ""))
                        : "expired".equals(st) ? "не доставлено: срок вышел" : st;
                sb.append(who).append(": ").append(text).append('\n');
            }
            ui.post(() -> { if (progress != null) progress.setText(sb.toString().trim()); });
        }, "knothop-invite-poll").start();
    }

    private static Bitmap renderQr(String content, int size) throws Exception {
        Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
        hints.put(EncodeHintType.MARGIN, 2);
        hints.put(EncodeHintType.CHARACTER_SET, "ISO-8859-1");
        BitMatrix m = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size, hints);
        int w = m.getWidth(), h = m.getHeight();
        int[] px = new int[w * h];
        for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) px[y * w + x] = m.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
        return Bitmap.createBitmap(px, w, h, Bitmap.Config.ARGB_8888);
    }

    private void wipe() {
        ui.removeCallbacks(poll);
        invite = null;
        if (inviteText != null) inviteText.setText("");
        if (qrView != null) qrView.setImageBitmap(null);
        if (qr != null) { qr.recycle(); qr = null; }
    }

    @Override protected void onStop() {
        super.onStop();
        if (sharing) { sharing = false; return; }
        wipe();
        resultBox.removeAllViews();
    }

    @Override protected void onDestroy() { wipe(); super.onDestroy(); }
}
