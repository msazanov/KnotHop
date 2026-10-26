package com.knothop.vpn;

import java.util.List;
import java.util.Locale;

/** Подписи экрана маршрутизации: имена выходов, действий и категорий списков. Без доступа к файлам и без побочных эффектов. */
final class RoutingLabels {
    private final List<RoutingCfg.Node> nodes;

    RoutingLabels(List<RoutingCfg.Node> nodes) { this.nodes = nodes; }

    boolean known(String hex) {
        for (RoutingCfg.Node n : nodes) if (n.d.equals(hex)) return true;
        return false;
    }

    String nameOf(String hex) {
        for (RoutingCfg.Node n : nodes) if (n.d.equals(hex)) return TopologyView.shortName(n.n);
        return hex.length() >= 8 ? hex.substring(0, 8) : hex;
    }

    /** Короткое описание действия: default, direct или exit:&lt;hex&gt;. */
    String action(String a) {
        if (a == null) return "";
        if (a.equals("default")) return "выход по умолчанию";
        if (a.equals("direct")) return "мимо VPN ⚠";
        if (a.startsWith("exit:")) {
            String d = a.substring(5).toLowerCase(Locale.ROOT);
            return known(d) ? "через " + nameOf(d) : "через неизвестный выход " + nameOf(d);
        }
        return "неизвестное действие";
    }

    /** Название правила по спискам: «сайты YOUTUBE (YouTube)» или «подсети RU (Россия)». */
    static String ruleTitle(RoutingCfg.Rule r) {
        String h = hint(r.type, r.name);
        return (r.geoip() ? "Подсети " : "Сайты ") + r.name + (h.isEmpty() ? "" : " (" + h + ")");
    }

    static String hint(String type, String name) {
        switch (type + ":" + name.toUpperCase(Locale.ROOT)) {
            case "geoip:RU": return "Россия";
            case "geoip:BY": return "Беларусь";
            case "geoip:PRIVATE": return "локальные сети";
            case "geoip:RU-BLOCKED": return "заблокированные в РФ";
            case "geoip:RU-WHITELIST": return "белый список РФ";
            case "geosite:RU-BLOCKED": return "заблокированные в РФ";
            case "geosite:CATEGORY-RU": return "российские сайты";
            case "geosite:YOUTUBE": return "YouTube";
            case "geosite:GOOGLE": return "Google";
            case "geosite:TELEGRAM": return "Telegram";
            case "geosite:CATEGORY-ADS-ALL": return "реклама";
            default: return "";
        }
    }

    static String size(long bytes) {
        return bytes >= (1 << 20) ? (bytes >> 20) + " МБ" : (bytes >> 10) + " КБ";
    }

    // ---------------------------------------------------------------- пояснения

    static final String MODE_ALL_TITLE = "Весь трафик через выход";
    static final String MODE_ALL_DESC = "Все приложения идут через выход по умолчанию. Сохранённые правила не действуют.";
    static final String MODE_RULES_TITLE = "По правилам";
    static final String MODE_RULES_DESC = "Выбранные сайты, подсети и списки идут через другой выход или мимо VPN, всё остальное — через выход по умолчанию.";

    static final String DEFAULT_EXIT_AUTO = "Выход не выбран вручную: телефон сам берёт выход с наименьшей задержкой и при отказе переходит на другой.";
    static final String DEFAULT_EXIT_PICKED = "Выбран вручную на главном экране. Если он недоступен, работа продолжается через лучший из доступных, а при возвращении выбранный выход снова становится основным.";

    static final String ORDER_NOTE = "Порядок проверки (это не рейтинг выходов): сначала «Свои адреса и домены» сверху вниз, затем «Списки» сверху вниз. "
            + "Действует первое совпавшее правило; если совпадений нет, трафик идёт через выход по умолчанию. "
            + "Исключение: подсети с действием «Мимо VPN» система исключает из туннеля при подключении, поэтому они срабатывают раньше остальных правил.";

    static final String DIRECT_WARNING = "Трафик к этим адресам пойдёт напрямую, не через выход. Сайты увидят ваш настоящий адрес, туннель этот трафик не защищает, "
            + "и при сбое VPN (когда остальной трафик блокируется) он продолжит идти напрямую. Действует после переподключения VPN.";

    static final String DIRECT_ONLY_IP = "«Мимо VPN» доступно только для подсетей (IP), для сайтов нет";

    static final String DOMAIN_NOTE = "Правила по сайтам узнают адрес из DNS-ответов, прошедших через VPN: DNS-over-HTTPS и «Безопасный DNS» браузера их скрывают. "
            + "Пока такие правила включены, DNS по TLS (порт 853) блокируется, чтобы «Частный DNS» Android вернулся к обычному DNS. "
            + "«Мимо VPN» работает по IP-подсетям (например, список RU) и применяется при подключении; больше 10 000 подсетей система не принимает, мелкие блоки идут через VPN.";
}
