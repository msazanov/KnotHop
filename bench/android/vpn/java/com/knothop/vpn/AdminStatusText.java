package com.knothop.vpn;

import org.json.JSONObject;

/**
 * Человекочитаемые тексты ответов backend admin-view/admin-submit/admin-status (контракт
 * docs/proposals/admin-backend-interface-2026-10-23.md). Не зависит от Android: проверяется на JVM
 * (test/com/knothop/vpn/AdminStatusTextCheck.java). Ничего не решает за backend: только честно пересказывает.
 *
 * <p>Правила: «доступ отозван»/«доступ выдан» говорится только по {@code effective_host_allowed};
 * {@code record_committed} сам по себе не успех ACL; {@code unknown} не превращается ни в applied, ни в rejected,
 * ни в вечный pending; pending/delivered — применение не подтверждено.
 */
final class AdminStatusText {
    static final String OP_STATUS = "status.get", OP_GRANT = "rights.grant", OP_REVOKE = "rights.revoke";
    /** Срок жизни запроса на target-ноде (10 минут): дольше ждать ответа бессмысленно. */
    static final long REQUEST_TTL_SEC = 600;

    private AdminStatusText() { }

    /** Состояние команды (admin-view.commands[], admin-status) одной строкой для пользователя. */
    static String describe(String op, String state, boolean durableAck, JSONObject result, long ageSec) {
        String s = state == null ? "" : state;
        String code = str(result, "code");
        String codeText = code.isEmpty() ? "" : " — " + reason(code);
        boolean rights = OP_GRANT.equals(op) || OP_REVOKE.equals(op);
        switch (s) {
            case "applied":
            case "applied_not_effective":
                if (!durableAck) return "Противоречивые данные: нет долговечного подтверждения ноды. Не считать применённым.";
                return rights ? rightsOutcome(op, s, code, result) : (OP_STATUS.equals(op)
                        ? "Статус получен и подтверждён нодой." : "Нода подтвердила применение.");
            case "pending":
                return ageSec > REQUEST_TTL_SEC
                        ? "Ответа нет больше 10 минут: срок запроса, вероятно, истёк. Исход неизвестен: запись могла сохраниться без ответа. Обновите статус и проверьте права вручную."
                        : "Ожидает отправки или ответа ноды (до 10 минут). Применение не подтверждено." + codeText;
            case "delivered":
                return ageSec > REQUEST_TTL_SEC
                        ? "Доставлено, но подтверждения применения нет больше 10 минут. Исход неизвестен: запись могла сохраниться без ответа. Обновите статус и проверьте права вручную."
                        : "Доставлено ноде. Применение ещё не подтверждено.";
            case "rejected":
                return "Отклонено" + (codeText.isEmpty() ? "." : codeText + ".")
                        + (durableAck ? "" : " Отказ не зафиксирован в журнале ноды.");
            case "stale":
                return "Устарело" + (codeText.isEmpty() ? "." : codeText + ".") + " Изменений не внесено; обновите статус и повторите.";
            case "expired":
                if (!durableAck) return "Истёк срок ожидания подтверждения. Исход неизвестен: запись могла сохраниться на ноде без ответа."
                        + " Нажмите «Обновить» и проверьте права вручную.";
                return "Нода подтвердила истечение срока запроса" + (codeText.isEmpty() ? "." : codeText + ".")
                        + " Проверьте текущие права после обновления.";
            case "unknown":
                return "Исход неизвестен" + codeText + ". Автоматически запрос не повторяется: нажмите «Обновить» и сверьте права участников."
                        + " Не считайте его ни применённым, ни отклонённым.";
            default:
                return "Неизвестное состояние «" + clean(s, 24) + "». Не считать применённым.";
        }
    }

    /** Итог rights.grant/rights.revoke по действующему решению ноды, а не по факту записи. */
    private static String rightsOutcome(String op, String state, String code, JSONObject result) {
        boolean grant = OP_GRANT.equals(op);
        Boolean effective = tri(result, "effective_host_allowed");
        boolean committed = Boolean.TRUE.equals(tri(result, "record_committed"));
        Boolean changed = tri(result, "changed");
        boolean notEffective = "applied_not_effective".equals(state) || "record_committed_not_effective".equals(code)
                || (effective != null && effective != grant);
        if (notEffective) {
            String what = grant ? "выдаче" : "отзыве";
            String now = effective == null ? "итоговое решение ноды не совпало с запросом"
                    : effective ? "по решению ноды доступ действует" : "по решению ноды доступа нет";
            return (grant ? "Доступ НЕ выдан" : "Доступ НЕ отозван") + ": " + (committed ? "запись о " + what + " сохранена, но " : "")
                    + now + " (например, более приоритетная запись корня). Проверьте права участника после обновления.";
        }
        String same = Boolean.FALSE.equals(changed) ? " Состояние уже было таким, изменений нет." : "";
        if (effective == null) {
            return "Нода подтвердила применение, но не сообщила действующий доступ (ответ старого формата): "
                    + (grant ? "выдача" : "отзыв") + " не подтверждены. Проверьте права после обновления." + same;
        }
        return (grant ? "Доступ выдан: нода подтвердила, что доступ действует." : "Доступ отозван: нода подтвердила, что доступа нет.") + same;
    }

    /** Ответ admin-submit для пользователя. */
    static String submit(JSONObject r, String op) {
        if (r == null) return "Backend не вернул ответ. Запрос не считается отправленным.";
        if (!r.optBoolean("accepted", false)) {
            String why = str(r, "rejected");
            return "Запрос не отправлен: " + (why.isEmpty() ? "причина не сообщена" : reason(why)) + ". Ничего не изменено.";
        }
        String state = str(r, "state");
        if (r.optBoolean("queued", false) && (state.isEmpty() || "pending".equals(state))) {
            return "Запрос поставлен в очередь прямой отправки LXMF. Это не доставка и не применение: результат появится в списке команд.";
        }
        return "Запрос уже есть на этом телефоне. " + describe(op, state, false, null, 0)
                + (state.isEmpty() ? "" : " Подробности — в списке команд.");
    }

    /** Подпись состояния ноды из admin-view.node. */
    static String nodeState(String status, boolean stale) {
        String base = "authenticated".equals(status) ? "подтверждено подписанным ответом ноды"
                : "unknown".equals(status) ? "неизвестно: подписанного ответа ноды пока нет, нажмите «Обновить»" : clean(status, 40);
        return base + (stale ? " · данные устарели" : "");
    }

    /** Причины/коды backend (effective_authority.reason, capabilities.reason, code, rejected). */
    static String reason(String code) {
        if (code == null || code.isEmpty()) return "причина не сообщена";
        switch (code) {
            case "NO_HOST_AUTHORITY":
            case "no_host_authority":
            case "target_no_host_authority":
                return "нода не дала этому корню полномочий на HOST_ACCESS (нужна запись в host-policy.json у оператора ноды; принятого якоря недостаточно). Доступом на этой ноде управлять нельзя";
            case "authenticated_target_status": return "права подтверждены ответом ноды";
            case "last_authenticated_target_status_stale": return "последний ответ ноды устарел, команды отключены до обновления";
            case "target_status_not_authenticated":
            case "target_root_status_not_authenticated": return "ответ ноды для этого корня ещё не получен: доступен только запрос статуса";
            case "no_accepted_root_chain_for_target": return "нет принятого корня, по которому эта нода входит в вашу сеть";
            case "trust_state_unavailable": return "локальное хранилище доверия недоступно";
            case "local_identity_unavailable": return "локальная identity недоступна";
            case "unsupported_offline": return "VPN/LXMF сейчас не активен: запрос не поставлен в очередь, включите VPN";
            case "lxmf_runtime_not_ready": return "LXMF на телефоне ещё не готов";
            case "target_not_in_authenticated_snapshot": return "нода не найдена в проверенном локальном снимке";
            case "target_identity_unknown": return "identity ноды неизвестна";
            case "target_not_in_selected_root": return "нода не входит в выбранный корень";
            case "target_identity_destination_mismatch": return "адрес ноды не соответствует её identity";
            case "target_capability_unknown": return "возможности ноды неизвестны: сначала обновите статус";
            case "target_capability_stale": return "сведения о ноде устарели (старше 10 минут): обновите статус";
            case "target_host_access_unavailable": return "нода не готова управлять HOST_ACCESS (ACL недоступен)";
            case "target_authority_changed": return "ваши полномочия на ноде изменились: обновите статус";
            case "insufficient_scoped_authority": return "недостаточно полномочий в выбранном корне для этой ноды";
            case "holder_not_known_in_selected_root": return "участник не известен в выбранном корне";
            case "no_status_authority": return "нет права запрашивать статус (нужно ADD, REMOVE или CONFIG)";
            case "client_admin_queue_full": return "очередь админ-запросов на телефоне заполнена";
            case "lxmf_send_queue_full": return "очередь отправки LXMF заполнена";
            case "request_id_conflict": return "идентификатор запроса уже использован для другого действия";
            case "expired": return "срок запроса истёк";
            case "expiry_out_of_bounds": return "срок запроса вне допустимых границ";
            case "backend_error": return "внутренняя ошибка backend";
            case "invalid_cli_input": return "backend отверг формат команды";
            case "invalid_target": return "некорректный адрес ноды";
            case "invalid_request_id": return "некорректный идентификатор запроса";
            case "root_not_accepted": return "корень не принят нодой";
            case "unsupported_operation_or_authority": return "операция не поддерживается или нет полномочий";
            case "unsupported_operation": return "операция не поддерживается";
            case "wrong_target_or_scope": return "запрос адресован другой ноде или области";
            case "journal_quota_exceeded": return "журнал ноды переполнен для этого администратора";
            case "journal_unreadable": return "запись в журнале ноды нечитаема, исход неизвестен";
            case "host_acl_unavailable": return "ACL ноды не готов";
            case "host_commit_failed": return "нода не смогла сохранить запись, изменений нет";
            case "stale_rights_snapshot": return "права участника изменились с момента снимка";
            case "stale_host_record": return "запись HOST_ACCESS изменилась на ноде";
            case "record_committed_not_effective": return "запись сохранена, но итоговое решение ноды не совпало с запросом";
            case "direct_transport_retry": return "прямая отправка не удалась, будет повтор";
            default: return "код «" + clean(code, 40) + "»";
        }
    }

    private static String str(JSONObject o, String key) {
        // На Android optString(JSON null) даёт "null": сначала проверяем isNull.
        return o == null || !o.has(key) || o.isNull(key) ? "" : o.optString(key, "");
    }

    private static Boolean tri(JSONObject o, String key) {
        Object v = o == null || o.isNull(key) ? null : o.opt(key);
        return v instanceof Boolean ? (Boolean) v : null;
    }

    private static String clean(String s, int max) {
        if (s == null) return "";
        String v = s.replaceAll("[\\p{Cntrl}]", " ");
        return v.length() > max ? v.substring(0, max) + "…" : v;
    }
}
