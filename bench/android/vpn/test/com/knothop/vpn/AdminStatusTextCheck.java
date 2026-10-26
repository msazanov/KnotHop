package com.knothop.vpn;

import org.json.JSONObject;

/**
 * Проверка AdminStatusText на JVM (без Android): java -cp out:json.jar com.knothop.vpn.AdminStatusTextCheck.
 * Нужен org.json (в android.jar только заглушки). В APK не входит: build.sh компилирует только каталог java/.
 */
public final class AdminStatusTextCheck {
    private static int fails;

    private static void check(boolean ok, String what) {
        if (!ok) { fails++; System.out.println("FAIL: " + what); }
    }

    private static JSONObject j(String s) throws Exception { return new JSONObject(s); }

    private static String d(String op, String state, boolean durable, String result, long age) throws Exception {
        return AdminStatusText.describe(op, state, durable, result == null ? null : j(result), age);
    }

    public static void main(String[] args) throws Exception {
        final String G = "rights.grant", R = "rights.revoke", S = "status.get";

        // отзыв: «доступ отозван» только при effective_host_allowed == false
        String t = d(R, "applied", true, "{\"state\":\"applied\",\"code\":null,\"record_committed\":true,\"effective_host_allowed\":false,\"changed\":true}", 5);
        check(t.startsWith("Доступ отозван"), "revoke effective=false -> отозван: " + t);
        t = d(R, "applied", true, "{\"record_committed\":true,\"effective_host_allowed\":false,\"changed\":false}", 5);
        check(t.startsWith("Доступ отозван") && t.contains("изменений нет"), "revoke unchanged: " + t);
        t = d(R, "applied_not_effective", true, "{\"code\":\"record_committed_not_effective\",\"record_committed\":true,\"effective_host_allowed\":true,\"changed\":false}", 5);
        check(t.startsWith("Доступ НЕ отозван") && t.contains("доступ действует"), "revoke not effective: " + t);
        check(!t.contains("Доступ отозван"), "not effective never says revoked");
        // record_committed сам не успех, даже если backend прислал applied с effective=true
        t = d(R, "applied", true, "{\"record_committed\":true,\"effective_host_allowed\":true}", 5);
        check(t.startsWith("Доступ НЕ отозван"), "applied+effective=true on revoke is not revoked: " + t);
        t = d(R, "applied", true, "{\"record_committed\":true,\"code\":\"record_committed_not_effective\"}", 5);
        check(t.startsWith("Доступ НЕ отозван"), "code only -> not effective: " + t);
        // старый ответ без полей: ни «отозван», ни «выдан»
        t = d(R, "applied", true, "{\"state\":\"applied\",\"code\":null}", 5);
        check(!t.startsWith("Доступ отозван") && t.contains("не сообщила действующий доступ"), "old reply: " + t);
        t = d(G, "applied", true, "{\"code\":null}", 5);
        check(!t.startsWith("Доступ выдан") && t.contains("не сообщила"), "old grant reply: " + t);
        // выдача
        t = d(G, "applied", true, "{\"record_committed\":true,\"effective_host_allowed\":true,\"changed\":true}", 5);
        check(t.startsWith("Доступ выдан"), "grant effective=true: " + t);
        t = d(G, "applied_not_effective", true, "{\"record_committed\":true,\"effective_host_allowed\":false}", 5);
        check(t.startsWith("Доступ НЕ выдан") && t.contains("доступа нет"), "grant not effective: " + t);
        t = d(G, "applied", true, "{\"record_committed\":false,\"effective_host_allowed\":false}", 5);
        check(t.startsWith("Доступ НЕ выдан") && !t.contains("запись о выдаче сохранена"), "grant record_committed=false: " + t);
        // applied без durable ACK не показывается как применённый
        t = d(G, "applied", false, "{\"effective_host_allowed\":true}", 5);
        check(t.startsWith("Противоречивые данные"), "applied w/o durable: " + t);
        // status.get
        check(d(S, "applied", true, "{\"code\":null}", 1).startsWith("Статус получен"), "status applied");

        // pending/delivered не applied и не висят вечно
        t = d(G, "pending", false, null, 30);
        check(t.contains("Применение не подтверждено") && !t.contains("Доступ выдан"), "pending: " + t);
        t = d(G, "pending", false, "{\"code\":\"direct_transport_retry\"}", 30);
        check(t.contains("повтор"), "pending retry code: " + t);
        t = d(G, "pending", false, null, 601);
        check(t.contains("истёк") && t.contains("Исход неизвестен") && t.contains("без ответа"), "pending old: " + t);
        t = d(G, "delivered", false, null, 30);
        check(t.contains("Применение ещё не подтверждено"), "delivered: " + t);
        t = d(G, "delivered", false, null, 700);
        check(t.contains("Исход неизвестен") && t.contains("без ответа"), "delivered old: " + t);

        // unknown: ни applied, ни rejected, ни pending; нужна ручная проверка
        t = d(G, "unknown", false, "{\"code\":\"journal_unreadable\"}", 5);
        check(t.startsWith("Исход неизвестен") && t.contains("Обновить") && t.contains("ни применённым, ни отклонённым"), "unknown: " + t);
        check(!t.contains("Ожидает"), "unknown not pending");
        t = d(G, "unknown", false, null, 5000);
        check(t.startsWith("Исход неизвестен"), "unknown no result: " + t);

        // rejected / stale / expired
        t = d(G, "rejected", true, "{\"code\":\"no_host_authority\"}", 5);
        check(t.startsWith("Отклонено") && t.contains("host-policy.json"), "rejected no_host_authority: " + t);
        t = d(G, "rejected", false, "{\"code\":\"host_commit_failed\"}", 5);
        check(t.contains("не зафиксирован"), "non-durable rejected: " + t);
        check(d(G, "stale", true, "{\"code\":\"stale_rights_snapshot\"}", 5).startsWith("Устарело"), "stale");
        t = d(G, "expired", false, null, 601);
        check(t.startsWith("Истёк срок") && t.contains("Исход неизвестен") && t.contains("без ответа"), "expired without ACK remains unknown: " + t);
        check(!t.contains("Не применено") && !t.contains("Доступ выдан"), "expired without ACK never claims non-application");
        t = d(R, "expired", false, "{\"code\":\"expired\"}", 601);
        check(t.contains("Исход неизвестен") && !t.contains("Доступ отозван"), "expired revoke without ACK is not revoked");
        t = d(G, "expired", true, "{\"code\":\"expired\"}", 601);
        check(t.startsWith("Нода подтвердила") && !t.contains("Не применено"), "target-confirmed expiry does not imply current rights: " + t);
        check(d(G, "weird\u0001", false, null, 5).startsWith("Неизвестное состояние"), "unknown state string");

        // admin-submit
        check(AdminStatusText.submit(j("{\"version\":1,\"accepted\":true,\"requestid\":\"a\",\"queued\":true,\"state\":\"pending\"}"), G)
                .contains("не доставка и не применение"), "submit queued");
        t = AdminStatusText.submit(j("{\"version\":1,\"accepted\":false,\"requestid\":\"\",\"queued\":false,\"rejected\":\"unsupported_offline\"}"), G);
        check(t.contains("не поставлен в очередь") && t.contains("Ничего не изменено"), "submit offline: " + t);
        t = AdminStatusText.submit(j("{\"version\":1,\"accepted\":false,\"queued\":false,\"rejected\":\"target_no_host_authority\"}"), G);
        check(t.contains("host-policy.json"), "submit no host authority: " + t);
        t = AdminStatusText.submit(j("{\"version\":1,\"accepted\":true,\"queued\":false,\"state\":\"unknown\"}"), G);
        check(t.contains("Исход неизвестен"), "submit idempotent unknown: " + t);
        check(AdminStatusText.submit(null, G).contains("не считается отправленным"), "submit null");
        check(AdminStatusText.submit(j("{\"accepted\":false}"), G).contains("причина не сообщена"), "submit no reason");

        // коды причин и состояние ноды
        check(AdminStatusText.reason("NO_HOST_AUTHORITY").contains("host-policy.json"), "reason NO_HOST_AUTHORITY");
        check(AdminStatusText.reason("no_host_authority").contains("host-policy.json"), "reason no_host_authority");
        check(AdminStatusText.reason("some_new_code").contains("some_new_code"), "reason unknown code echoed");
        check(AdminStatusText.nodeState("unknown", true).contains("Обновить") && AdminStatusText.nodeState("unknown", true).contains("устарели"), "node unknown stale");
        check(AdminStatusText.nodeState("authenticated", false).contains("подписанным"), "node authenticated");

        System.out.println(fails == 0 ? "OK" : "FAILED: " + fails);
        if (fails != 0) System.exit(1);
    }
}
