package com.knothop.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.text.InputFilter;
import android.widget.EditText;

import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/** Имя этого телефона в сети: state/node-name.txt. Нет файла - нативная часть использует автоимя «телефон-XXXXXX» (по хешу ключа). */
final class NodeName {
    static final int MAX = 32;

    private NodeName() { }

    private static File file(File filesDir) { return new File(new File(filesDir, "state"), "node-name.txt"); }

    static String get(File filesDir) { return Util.read(file(filesDir)).trim(); }

    /** Автоимя, которое нативная часть даёт без заданного: пусто, пока ключ не создан (whoami.json ещё нет). */
    static String auto(File filesDir) {
        try {
            String h = new JSONObject(Util.read(new File(new File(filesDir, "state"), "whoami.json"))).optString("hash", "");
            return h.length() >= 6 ? "телефон-" + h.substring(0, 6) : "";
        } catch (Throwable ignored) { return ""; }
    }

    /** Имя не задано или совпадает с автоименем. */
    static boolean isAuto(File filesDir) {
        String n = get(filesDir);
        return n.isEmpty() || n.equals(auto(filesDir));
    }

    /** Пустое имя возвращает автоимя. Запись атомарная; новое имя узлы узнают при следующем подключении к выходу. */
    static void set(File filesDir, String name) {
        File f = file(filesDir);
        String n = name.trim();
        if (n.length() > MAX) n = n.substring(0, MAX);
        try {
            Files.createDirectories(f.getParentFile().toPath());
            if (n.isEmpty()) { f.delete(); return; }
            File tmp = new File(f.getPath() + ".tmp");
            Files.write(tmp.toPath(), n.getBytes(StandardCharsets.UTF_8));
            Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Throwable e) {
            Util.lab("имя не сохранено: " + e);
        }
    }

    /** Диалог ввода имени. `done` вызывается при любом закрытии (сохранить или пропустить). */
    static AlertDialog dialog(Activity a, File filesDir, Runnable done) {
        EditText in = new EditText(a);
        in.setSingleLine(true);
        in.setFilters(new InputFilter[]{new InputFilter.LengthFilter(MAX)});
        String cur = get(filesDir), auto = auto(filesDir);
        in.setText(cur);
        in.setHint(auto.isEmpty() ? "телефон-…" : auto);
        return new AlertDialog.Builder(a).setTitle("Имя этого телефона")
                .setMessage("Так телефон будут видеть в сети нод. Оставьте пустым, чтобы использовать автоматическое имя" + (auto.isEmpty() ? "." : " (" + auto + ")."))
                .setView(in)
                .setPositiveButton("Сохранить", (d, w) -> { set(filesDir, in.getText().toString()); done.run(); })
                .setNegativeButton("Пропустить", (d, w) -> done.run())
                .setOnCancelListener(d -> done.run())
                .show();
    }
}
