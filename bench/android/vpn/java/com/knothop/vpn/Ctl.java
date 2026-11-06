package com.knothop.vpn;

import org.json.JSONObject;

import java.io.File;

/** Мост к нативному ядру (ADR 0028): JSON-запрос локального владельца → JSON-ответ. Живое ядро процесса; без него - просмотр таблицы с диска. */
final class Ctl {
    private Ctl() { }

    static File state(android.content.Context c) { return new File(c.getFilesDir(), "state"); }

    /** Выполняет запрос; при ошибке возвращает объект {"ok":false,"error":...}. Вызывать не на главном потоке. */
    static JSONObject call(android.content.Context c, JSONObject req) {
        String sd = state(c).getAbsolutePath();
        try {
            return new JSONObject(Native.runCLI(req.toString(), sd));
        } catch (Throwable e) {
            try { return new JSONObject().put("ok", false).put("error", String.valueOf(e.getMessage())); } catch (Exception x) { return new JSONObject(); }
        }
    }

    static JSONObject req(String cmd) {
        try { return new JSONObject().put("cmd", cmd); } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
