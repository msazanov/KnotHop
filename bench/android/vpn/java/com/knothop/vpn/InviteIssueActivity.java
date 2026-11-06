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
 * Один экран выпуска приглашения (ADR 0028 §2.2-2.5): «Сервер (первый запуск)», «Пользователь» или «Админ». Для пользователя и админа
 * выбираются ноды, где приглашение должно быть погашено: на каждую уходит команда «ожидай» (invite.add), у каждой ноды свой пин.
 * Экран закрыт FLAG_SECURE; строка и QR стираются при уходе с экрана и не пишутся в журнал.
 */
public final class InviteIssueActivity extends Activity {
    private static final int[] TTL_H = {6, 24, 48, 168};
    private static final String[] TTL_NAMES = {"6 часов", "сутки", "48 часов", "7 суток"};
    private LinearLayout box, nodeBox, resultBox;
    private RadioGroup preset, ttl;
    private final List<CheckBox> nodeBoxes = new ArrayList<>();
    private final List<String> nodeHashes = new ArrayList<>();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private String invite;
    private ImageView qrView;
    private TextView inviteText, progress;
    private Bitmap qr;
    private JSONArray requests;
    private boolean sharing;
    private final Runnable poll = new Runnable() {
        @Override public void run() { pollOutbox(); ui.postDelayed(this, 2500); }
    };

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
        kind.addView(Ui.titleWithHelp(this, "Для кого", "«Сервер»: первый запуск новой ноды (она станет управляться этим телефоном). «Пользователь»: телефон или ПК, "
                + "получит USE на выбранных нодах (выход в интернет — свойство самой ноды). «Админ»: получит CONFIG, ADD, REMOVE и USE на выбранных нодах."));
        preset = new RadioGroup(this);
        String[] names = {"Сервер — первый запуск", "Пользователь", "Админ"};
        for (int i = 0; i < names.length; i++) {
            RadioButton r = new RadioButton(this);
            r.setId(100 + i);
            r.setText(names[i]);
            r.setTextColor(Ui.TEXT);
            preset.addView(r);
        }
        preset.check(101);
        preset.setOnCheckedChangeListener((g, id) -> showNodes());
        kind.addView(preset);
        box.addView(kind, Ui.cardParams(this));
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
        box.addView(Ui.primary(this, "Выпустить", v -> issue()), Ui.cardParams(this));
        resultBox = new LinearLayout(this);
        resultBox.setOrientation(LinearLayout.VERTICAL);
        box.addView(resultBox);
        loadNodes();
    }

    private void loadNodes() {
        new Thread(() -> {
            JSONObject v = Ctl.call(this, Ctl.req("view"));
            ui.post(() -> fillNodes(v));
        }, "knothop-invite-nodes").start();
    }

    private void fillNodes(JSONObject v) {
        nodeHashes.clear();
        nodeBoxes.clear();
        JSONArray contacts = v.optJSONArray("contacts");
        JSONObject managed = v.optJSONObject("nodes");
        if (contacts != null) {
            for (int i = 0; i < contacts.length(); i++) {
                JSONObject c = contacts.optJSONObject(i);
                if (c == null || c.optInt("roles", 0) == 0) continue;
                String h = c.optString("hash");
                boolean mine = managed != null && managed.has(h);
                CheckBox cb = new CheckBox(this);
                cb.setTextColor(mine ? Ui.TEXT : Ui.MUTED);
                cb.setText(Rights.clip(c.optString("name", "")) + "  " + h.substring(0, 8) + "  ·  " + Rights.roles(c.optInt("roles")) + (mine ? "" : "  ·  не управляю"));
                cb.setEnabled(mine);
                nodeHashes.add(h);
                nodeBoxes.add(cb);
            }
        }
        showNodes();
    }

    private void showNodes() {
        nodeBox.removeAllViews();
        boolean server = preset.getCheckedRadioButtonId() == 100;
        nodeBox.addView(Ui.titleWithHelp(this, server ? "Нода" : "Где погасить",
                server ? "Приглашение сервера выпускается на этом телефоне: сервер вступит по строке (knothopd node --invite-file) и подчинится вам как админу."
                       : "Приглашение должно быть погашено на каждой из выбранных нод (у каждой свой пин). Выбираются только ноды, которыми вы управляете: "
                         + "им уходит команда «ожидай»; пока нода офлайн, команда ждёт и повторяется. Включите все ноды, через которые пользователь может ходить (в т.ч. транзитные)."));
        if (server) {
            nodeBox.addView(Ui.muted(this, "Этот телефон. Права сервера на вас: USE; ваши права на сервере: CONFIG, ADD, REMOVE, USE."));
            return;
        }
        if (nodeBoxes.isEmpty()) nodeBox.addView(Ui.muted(this, "Нет нод, которыми вы управляете. Сначала вступите в сеть сервера или выпустите «Сервер — первый запуск»."));
        for (CheckBox cb : nodeBoxes) {
            if (cb.getParent() != null) ((LinearLayout) cb.getParent()).removeView(cb);
            nodeBox.addView(cb);
        }
    }

    private void issue() {
        int pid = preset.getCheckedRadioButtonId();
        long ttlMs = TTL_H[Math.max(0, ttl.getCheckedRadioButtonId() - 200)] * 3600_000L;
        JSONObject req = Ctl.req("issue");
        try {
            req.put("ttl_ms", ttlMs);
            if (pid == 100) {
                req.put("rights", Rights.USE).put("mgmt", Rights.ADMIN);
            } else {
                JSONArray nodes = new JSONArray();
                for (int i = 0; i < nodeBoxes.size(); i++) {
                    if (nodeBoxes.get(i).isChecked()) nodes.put(new JSONObject().put("hash", nodeHashes.get(i)).put("rights", pid == 101 ? Rights.USER : Rights.ADMIN).put("mgmt", 0));
                }
                if (nodes.length() == 0) { resultMsg("Выберите хотя бы одну ноду."); return; }
                req.put("nodes", nodes);
            }
        } catch (Exception e) { resultMsg("Ошибка: " + e.getMessage()); return; }
        resultMsg("Выпускаю…");
        new Thread(() -> {
            JSONObject r = Ctl.call(this, req);
            ui.post(() -> show(r));
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
        if (requests == null || progress == null) return;
        new Thread(() -> {
            JSONObject v = Ctl.call(this, Ctl.req("view"));
            JSONArray ob = v.optJSONArray("outbox");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < requests.length(); i++) {
                JSONObject q = requests.optJSONObject(i);
                String h = q.optString("hash"), rid = q.optString("requestid"), st = "?";
                for (int j = 0; ob != null && j < ob.length(); j++) if (rid.equals(ob.optJSONObject(j).optString("rid"))) st = ob.optJSONObject(j).optString("state");
                sb.append(h.substring(0, 8)).append(": ").append("applied".equals(st) ? "готова" : "pending".equals(st) ? "ожидает уведомления" : st).append('\n');
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
