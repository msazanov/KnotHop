package com.knothop.vpn;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.view.MotionEvent;
import android.view.View;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Граф: телефон в центре, узлы группы вокруг.
 *  - сплошная толстая линия: через этот узел идёт трафик;
 *  - пунктир: путь RNS от телефона прямой (vis direct) и Link не в состоянии fail, трафик не идёт;
 *  - vis via: от телефона линии нет, узел подвешен тонкой пунктирной линией к своей nh (ноде следующего хопа);
 *  - vis none: линий нет, узел приглушён; Link fail - серый узел с причиной;
 *  - тонкие линии между узлами: связи нода-нода с живым Link (edges из status.json); без edges - связи текущего выхода по старой таблице.
 * Узлы окрашены в цвета флага страны (код из имени knothop-XX-...).
 * Поведение «на резинках»: узлы связаны пружинами с телефоном и мягко отталкиваются друг от друга; потяни телефон или узел пальцем -
 * остальные плавно тянутся следом и расходятся, после отпускания колеблются и успокаиваются; телефон слабой пружиной тянется к центру.
 * Короткое касание узла - выбрать выход; долгое нажатие - управление; двойное касание пустого места - встряхнуть.
 */
final class TopologyView extends View {
    interface OnPick { void pick(String dest, String name); }
    interface OnLongPick { void pick(String dest, String name); }

    static final class Node {
        String name = "?", dest = "", state = "seen", cc = "XX", carrier = "none";
        boolean visible, isVia;
        int hops = -1;
        double rtt = -1;
        String lk = "none", why = "";   // состояние RNS Link к узлу: up | fail | none; причина последнего отказа
        String pl = "";                // тип узла из T_AUTH_OK: server/<ОС>, app/<ОС>; "" - ещё не подключались
        String presence = "unknown";   // alive | reported | unknown; absence of reports is not death
        int ra;                         // сколько выходов сообщают, что видят узел живым соседом
        String vis = "", nh = "";       // путь RNS (R8): direct | via | none, "" - поля нет; nh - dest следующего хопа при via, "" - неизвестно
        float x, y;
        boolean moved;
        float mx, my;   // ручное положение (доля ширины/высоты)
    }

    /** Связь нода-нода из status.json (edges): недоверенная подсказка выхода; rtt < 0 - неизвестен. */
    static final class Edge {
        final String a, b;
        final double rtt;
        Edge(String a, String b, double rtt) { this.a = a; this.b = b; this.rtt = rtt; }
    }

    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint t = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final List<Node> nodes = new ArrayList<>();
    private final List<Edge> edges = new ArrayList<>();
    private boolean hasEdges;   // в status.json есть поле edges: тогда старая таблица соседей не рисуется
    /** физика: dest -> {x, y, vx, vy}; телефон хранится отдельно */
    private final Map<String, float[]> phys = new HashMap<>();
    private float phx, phy, phvx, phvy;
    private boolean physInit;
    private long lastFrame;
    private long settleUntil;
    /** Сколько после изменения картины граф может двигаться: за 1,5 с узлы замирали на полпути, будто приложение зависло. */
    private static final long SETTLE_MS = 8000;
    private String layoutKey = "";
    private boolean active = true;
    private String phoneLabel = "";
    private boolean up;
    private double phoneRtt = -1;
    private String viaDest = "";
    private OnPick onPick;
    private OnLongPick onLongPick;
    private Runnable onPhonePick;
    private boolean longPicked;
    /** Режим «расстояние по пингу»: чем меньше RTT, тем жёстче и короче пружина (узел притягивается сильнее); неизвестный RTT - как самый большой. */
    private boolean pingMode;
    private final float d;
    private Node dragNode;
    private boolean dragPhone, dragged;
    private float downX, downY;
    private long lastTapMs, lastPosLog;
    private final Runnable longPress = () -> {
        if (!dragged && dragNode != null && onLongPick != null) {
            longPicked = true;
            Ui.click(this);
            onLongPick.pick(dragNode.dest, dragNode.name);
        } else if (!dragged && dragPhone && onPhonePick != null) {
            longPicked = true;
            Ui.click(this);
            onPhonePick.run();
        }
    };

    TopologyView(Context c) {
        super(c);
        d = c.getResources().getDisplayMetrics().density;
        t.setTextAlign(Paint.Align.CENTER);
    }

    void setOnPick(OnPick o) { onPick = o; }
    void setOnLongPick(OnLongPick o) { onLongPick = o; }
    /** Тап или долгий тап по своему телефону (в центре графа): экран «Моя нода». */
    void setOnPhonePick(Runnable r) { onPhonePick = r; }

    void setPingMode(boolean on) {
        if (pingMode == on) return;
        pingMode = on;
        settleUntil = android.os.SystemClock.uptimeMillis() + SETTLE_MS;
        lastFrame = 0;
        if (active) invalidate();
    }

    /** RTT -> 0 (≤15 мс) … 1 (≥600 мс), по логарифму: разница 20 и 40 мс заметнее, чем 400 и 420. */
    static float pingNorm(double rtt) {
        if (rtt <= 0) return 1f;
        double x = (Math.log(rtt) - Math.log(15)) / (Math.log(600) - Math.log(15));
        return (float) Math.max(0, Math.min(1, x));
    }

    /** Цвет по пингу: зелёный (быстро) - жёлтый - красный (медленно). */
    static int pingColor(double rtt, int alpha) {
        float x = pingNorm(rtt);
        int r = x < 0.5f ? (int) (60 + 2 * x * 180) : 240, g = x < 0.5f ? 170 : (int) (170 - (x - 0.5f) * 2 * 120);
        return alpha << 24 | Math.max(0, Math.min(255, r)) << 16 | Math.max(0, Math.min(255, g)) << 8 | 40;
    }

    /** Пружина по пингу: {жёсткость-множитель, длина покоя в долях радиуса}. */
    private static float[] pingSpring(double rtt) {
        float x = pingNorm(rtt);
        return new float[]{1.6f - 1.3f * x, 0.55f + 0.5f * x};
    }

    private double edgeRtt(String a, String b) {
        for (Edge e : edges) if ((e.a.equals(a) && e.b.equals(b)) || (e.a.equals(b) && e.b.equals(a))) return e.rtt;
        return -1;
    }

    /** Экономия энергии: когда экран приложения не активен, анимация стоит и положение узлов не считается (физика идёт только из onDraw). */
    void setActive(boolean a) {
        active = a;
        lastFrame = 0;
        if (a) settleUntil = android.os.SystemClock.uptimeMillis() + SETTLE_MS;
        if (a) invalidate();
    }

    void update(JSONObject st) {
        List<Node> fresh = new ArrayList<>();
        up = "up".equals(st.optString("state"));
        phoneLabel = st.optString("ip", "");
        JSONObject cur = st.optJSONObject("current");
        viaDest = cur != null && !cur.isNull("via") ? cur.optString("via", "") : "";
        phoneRtt = cur != null && !cur.isNull("rtt_ms") ? cur.optDouble("rtt_ms", -1) : -1;
        JSONArray ex = st.optJSONArray("exits");
        if (ex != null) {
            for (int i = 0; i < ex.length(); i++) {
                JSONObject e = ex.optJSONObject(i);
                if (e == null) continue;
                Node n = new Node();
                n.name = e.optString("n", "?");
                n.dest = e.optString("d");
                n.state = e.optString("s", "seen");
                n.visible = e.optBoolean("v", false);
                n.carrier = e.optString("c", "none");
                n.hops = e.isNull("h") ? -1 : e.optInt("h", -1);
                n.rtt = e.isNull("r") ? -1 : e.optDouble("r", -1);
                n.lk = e.optString("lk", "none");   // старая нативная часть поля не пишет: none
                n.why = whyText(e.isNull("why") ? "" : e.optString("why", ""));
                n.vis = e.isNull("vis") ? "" : e.optString("vis", "");   // старая нативная часть поля не пишет: ""
                n.nh = e.isNull("nh") ? "" : e.optString("nh", "");
                n.presence = e.optString("presence", "unknown");
                n.pl = e.isNull("pl") ? "" : e.optString("pl", "");
                n.ra = e.optInt("ra", 0);
                n.cc = countryOf(n.name);
                n.isVia = !viaDest.isEmpty() && viaDest.equals(n.dest);
                fresh.add(n);
            }
        }
        int before;
        synchronized (nodes) {
            before = nodes.size();
            nodes.clear();
            nodes.addAll(fresh);
        }
        // связи нода-нода: [["<dest A>","<dest B>",rtt|null], ...]; дубли (A,B)/(B,A) и петли отбрасываем
        hasEdges = st.has("edges") && !st.isNull("edges");
        edges.clear();
        JSONArray ed = st.optJSONArray("edges");
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; ed != null && i < ed.length(); i++) {
            JSONArray pe = ed.optJSONArray(i);
            if (pe == null || pe.length() < 2) continue;
            String a = pe.optString(0), b = pe.optString(1);
            if (a.isEmpty() || a.equals(b) || !seen.add(a.compareTo(b) < 0 ? a + "|" + b : b + "|" + a)) continue;
            edges.add(new Edge(a, b, pe.isNull(2) ? -1 : pe.optDouble(2, -1)));
        }
        // Движение продлевается только при смене СОСТАВА узлов: от vis/nh/state (они меняются при каждом обновлении статуса)
        // раскладка не зависит, иначе карта не замирает и uiautomator не может дождаться простоя.
        java.util.TreeSet<String> shape = new java.util.TreeSet<>();
        for (Node n : fresh) shape.add(n.dest);
        String key = shape.toString() + (pingMode ? "|ping" : "");
        if (!key.equals(layoutKey)) {
            layoutKey = key;
            long now = android.os.SystemClock.uptimeMillis();
            // не продлеваем окно, если движение ещё идёт: «мигающий» состав узлов иначе не даст карте уснуть
            if (now >= settleUntil) {
                settleUntil = now + SETTLE_MS;
            }
        }
        if (before != fresh.size()) requestLayout();
        if (active) invalidate();
    }

    /** Подпись носителя: TCP/QUIC - это открытый сокет до узла, не рабочий путь RNS. */
    static String carrierName(String c) {
        return "tcp".equals(c) ? "TCP" : "quic".equals(c) ? "QUIC" : "—";
    }

    /** Причина отказа Link: короткая, одна строка (≤ 40 знаков). */
    static String whyText(String w) {
        if (w == null) return "";
        return w.length() > 40 ? w.substring(0, 40) + "…" : w;
    }

    /** Код страны из имени `knothop-XX-что-угодно`; иначе XX. */
    static String countryOf(String name) {
        String[] a = name.split("-");
        if (a.length >= 2 && a[1].length() == 2 && Character.isLetter(a[1].charAt(0))) return a[1].toUpperCase();
        return "XX";
    }

    private static final java.util.regex.Pattern RAW_NAME = java.util.regex.Pattern.compile("knothop-[A-Za-z]{2}-[^\\s,():;]+");

    /** Строка статуса или журнала с именами узлов вида `knothop-XX-имя`: заменяем их на флаг и страну, как в списках. */
    static String prettify(String text) {
        java.util.regex.Matcher m = RAW_NAME.matcher(text);
        StringBuffer b = new StringBuffer();
        while (m.find()) m.appendReplacement(b, java.util.regex.Matcher.quoteReplacement(shortName(m.group())));
        m.appendTail(b);
        return b.toString();
    }

    static String shortName(String name) {
        String cc = countryOf(name);
        String[] a = name.split("-", 3);
        if (a.length == 3 && a[0].equals("knothop")) {
            if (cc.equals("XX")) return plainName(a[2]);
            return flagOf(cc) + " " + countryName(cc) + " " + (a[2].length() > 9 ? a[2].substring(0, 9) : a[2]);
        }
        return plainName(name);
    }

    @Override
    protected void onMeasure(int w, int h) {
        int width = MeasureSpec.getSize(w);
        int extra = Math.max(0, nodes.size() - 6) * (int) (46 * d);   // больше узлов - выше поле
        setMeasuredDimension(width, (int) (Math.min(width, 420 * d) + extra + 0.5f));
    }

    private float cx() { return getWidth() / 2f; }
    private float cy() { return getHeight() / 2f; }
    private float radius() { return Math.min(getWidth() / 2f - 56 * d, getHeight() / 2f - 62 * d); }

    /** Положение узла на кольце вокруг центра (начальное и «домашнее»). */
    private float[] ringPos(int i, int n) {
        double a = Math.toRadians(-90 + 360.0 * i / Math.max(n, 1));
        return new float[]{(float) (cx() + radius() * Math.cos(a)), (float) (cy() + radius() * Math.sin(a))};
    }

    /** Один шаг пружинной модели. Возвращает «энергию» (сумма квадратов скоростей) для решения, нужна ли следующая перерисовка. */
    private float step(List<Node> ns, float dt) {
        int n = ns.size();
        if (!physInit) {
            phx = cx(); phy = cy(); phvx = phvy = 0;
            physInit = true;
        }
        // новые узлы появляются на кольце, исчезнувшие забываются
        java.util.Set<String> alive = new java.util.HashSet<>();
        for (int i = 0; i < n; i++) {
            Node x = ns.get(i);
            alive.add(x.dest);
            if (!phys.containsKey(x.dest)) {
                float[] r = ringPos(i, n);
                phys.put(x.dest, new float[]{r[0], r[1], 0, 0});
            }
        }
        phys.keySet().retainAll(alive);
        float rest = radius();
        final float NW = 104 * d, NH = 84 * d, PW = 70 * d, PH = 96 * d, K_OVERLAP = 14f;
        final float kNode = 38f, kPhoneHome = 5f, rep = 5200f * d * d, damp = 3.6f;
        float energy = 0;
        float pfx = -kPhoneHome * (phx - cx()), pfy = -kPhoneHome * (phy - cy());
        for (int i = 0; i < n; i++) {
            Node a = ns.get(i);
            float[] pa = phys.get(a.dest);
            float fx = 0, fy = 0;
            // резинка к телефону: тянет, если дальше «покоя», и толкает, если ближе; при vis via - к своей nh (путь RNS идёт через неё)
            float[] hp = "via".equals(a.vis) && !a.nh.isEmpty() && !a.nh.equals(a.dest) ? phys.get(a.nh) : null;
            float ax = hp != null ? hp[0] : phx, ay = hp != null ? hp[1] : phy;
            float dx = pa[0] - ax, dy = pa[1] - ay;
            float dist = (float) Math.sqrt(dx * dx + dy * dy) + 0.001f;
            float kk = kNode, rr = rest;
            if (pingMode) {
                float[] sp = pingSpring(hp != null ? edgeRtt(a.nh, a.dest) : a.rtt);
                kk = kNode * sp[0];
                rr = rest * sp[1];
            }
            float f = -kk * (dist - rr);
            fx += f * dx / dist;
            fy += f * dy / dist;
            if (hp == null) {   // телефон слегка чувствует натяжение (у via-узла оно уходит в nh)
                pfx -= 0.12f * f * dx / dist;
                pfy -= 0.12f * f * dy / dist;
            }
            // телефон: мягко выталкивает узел, если ячейки пересеклись
            {
                float ox = (NW + PW) / 2 - Math.abs(pa[0] - phx), oy = (NH + PH) / 2 - Math.abs(pa[1] - phy);
                if (ox > 0 && oy > 0) {
                    if (ox < oy) fx += (pa[0] >= phx ? 1 : -1) * ox * K_OVERLAP; else fy += (pa[1] >= phy ? 1 : -1) * oy * K_OVERLAP;
                    pfx -= 0.2f * (pa[0] >= phx ? 1 : -1) * (ox < oy ? ox * K_OVERLAP : 0);
                    pfy -= 0.2f * (pa[1] >= phy ? 1 : -1) * (ox < oy ? 0 : oy * K_OVERLAP);
                }
            }
            // узлы не слипаются: дальнее мягкое отталкивание + выталкивание при пересечении ячеек (пересекаться можно, но они расходятся)
            for (int j = 0; j < n; j++) {
                if (j == i) continue;
                float[] pb = phys.get(ns.get(j).dest);
                float ox = NW - Math.abs(pa[0] - pb[0]), oy = NH - Math.abs(pa[1] - pb[1]);
                if (ox > 0 && oy > 0) {
                    if (ox < oy) fx += (pa[0] >= pb[0] ? 1 : -1) * ox * K_OVERLAP; else fy += (pa[1] >= pb[1] ? 1 : -1) * oy * K_OVERLAP;
                }
                float ex = pa[0] - pb[0], ey = pa[1] - pb[1];
                float dd = ex * ex + ey * ey + 40f * d;
                float r = (pingMode ? 2.2f : 1f) * rep / dd;
                float de = (float) Math.sqrt(dd);
                fx += r * ex / de;
                fy += r * ey / de;
            }
            if (pingMode && hasEdges) {   // связи нода-нода: тоже пружины по их RTT
                for (Edge e : edges) {
                    String other = e.a.equals(a.dest) ? e.b : e.b.equals(a.dest) ? e.a : null;
                    float[] pb = other == null ? null : phys.get(other);
                    if (pb == null) continue;
                    float[] sp = pingSpring(e.rtt);
                    float ex = pb[0] - pa[0], ey = pb[1] - pa[1];
                    float de = (float) Math.sqrt(ex * ex + ey * ey) + 0.001f;
                    float fe = 1.5f * sp[0] * (de - rest * sp[1]);
                    fx += fe * ex / de;
                    fy += fe * ey / de;
                }
            }
            if (a == dragNode && dragged) continue;   // держим пальцем
            pa[2] += fx * dt;
            pa[3] += fy * dt;
            float k = (float) Math.exp(-damp * dt);
            pa[2] *= k;
            pa[3] *= k;
            pa[0] += pa[2] * dt;
            pa[1] += pa[3] * dt;
            float m = 30 * d;
            pa[0] = Math.max(m, Math.min(getWidth() - m, pa[0]));
            pa[1] = Math.max(m, Math.min(getHeight() - 40 * d, pa[1]));
            energy += pa[2] * pa[2] + pa[3] * pa[3];
        }
        if (!(dragPhone && dragged)) {
            phvx += pfx * dt / 3f;
            phvy += pfy * dt / 3f;
            float k = (float) Math.exp(-damp * dt);
            phvx *= k;
            phvy *= k;
            phx += phvx * dt;
            phy += phvy * dt;
            energy += phvx * phvx + phvy * phvy;
        }
        for (int i = 0; i < n; i++) {
            float[] pa = phys.get(ns.get(i).dest);
            ns.get(i).x = pa[0];
            ns.get(i).y = pa[1];
        }
        return energy;
    }

    // ------------------------------------------------------------------ имя, флаг, цвет

    /** Флаг страны эмодзи (региональные индикаторы); неизвестная страна - глобус. */
    static String flagOf(String cc) {
        if (cc == null || cc.length() != 2 || !Character.isLetter(cc.charAt(0)) || !Character.isLetter(cc.charAt(1)) || cc.equals("XX")) return "\uD83C\uDF10";
        StringBuilder b = new StringBuilder();
        for (char ch : cc.toUpperCase().toCharArray()) b.appendCodePoint(0x1F1E6 + (ch - 'A'));
        return b.toString();
    }

    /** Название страны на языке телефона; без кода страны - «?». */
    static String countryName(String cc) {
        if (cc == null || cc.equals("XX")) return "?";
        String n = new java.util.Locale("", cc).getDisplayCountry();
        return n == null || n.isEmpty() || n.equalsIgnoreCase(cc) ? cc : n;
    }

    /** Часть имени после `knothop-XX-` (то, что узел назвал сам); у прочих имён - всё имя. */
    static String suffixOf(String name) {
        String[] a = name.split("-", 3);
        return a.length == 3 && a[0].equals("knothop") ? a[2] : name;
    }

    /** Эмодзи в начале строки (одна графема: флаг, символ с модификатором); иначе "". */
    static String leadingEmoji(String s) {
        if (s == null || s.isEmpty()) return "";
        int cp = s.codePointAt(0);
        if (cp < 0x2190 || Character.isLetterOrDigit(cp)) return "";
        int end = Character.charCount(cp);
        // регионы-флаги (два индикатора), модификаторы цвета кожи, вариант-селектор и склейка ZWJ
        if (cp >= 0x1F1E6 && cp <= 0x1F1FF && s.length() > end) {
            int c2 = s.codePointAt(end);
            if (c2 >= 0x1F1E6 && c2 <= 0x1F1FF) end += Character.charCount(c2);
        }
        while (end < s.length()) {
            int c2 = s.codePointAt(end);
            if (c2 == 0xFE0F || c2 == 0x200D || (c2 >= 0x1F3FB && c2 <= 0x1F3FF)) {
                end += Character.charCount(c2);
                if (c2 == 0x200D && end < s.length()) end += Character.charCount(s.codePointAt(end));
            } else break;
        }
        return s.substring(0, end);
    }

    /** Надпись в кружке: эмодзи в начале имени узла, иначе код страны (имя хоста по умолчанию ничего не говорит). */
    static String badgeOf(String name, String cc) {
        String e = leadingEmoji(suffixOf(name).trim());
        if (!e.isEmpty()) return e;
        return cc == null || cc.equals("XX") ? "?" : cc;
    }

    /** Устойчивый цвет узла из его dest (или имени): оттенок из хеша, два уровня яркости, чтобы соседние оттенки различались. */
    static int colorOf(String key) {
        int h = 0x811C9DC5;
        for (int i = 0; i < key.length(); i++) h = (h ^ key.charAt(i)) * 0x01000193;
        h ^= h >>> 15; h *= 0x2C1B3C6D; h ^= h >>> 12;
        float hue = (h & 0xFFFF) % 360;
        boolean light = ((h >>> 16) & 1) == 1;
        return android.graphics.Color.HSVToColor(new float[]{hue, light ? 0.50f : 0.70f, light ? 0.92f : 0.68f});
    }

    private final Map<String, Bitmap> flagBmp = new HashMap<>();

    /** Эмодзи флага, обрезанный по видимым пикселям (шрифт даёт вокруг пустые поля); null - шрифт флага не нарисовал. */
    private Bitmap flagBitmap(String cc) {
        if (flagBmp.containsKey(cc)) return flagBmp.get(cc);
        Bitmap res = null;
        try {
            String f = flagOf(cc);
            Paint q = new Paint(Paint.ANTI_ALIAS_FLAG);
            q.setTextSize(160);
            Bitmap full = Bitmap.createBitmap(320, 260, Bitmap.Config.ARGB_8888);
            new Canvas(full).drawText(f, 20, 180, q);
            int w = full.getWidth(), h = full.getHeight();
            int[] px = new int[w * h];
            full.getPixels(px, 0, w, 0, 0, w, h);
            int x0 = w, y0 = h, x1 = -1, y1 = -1;
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                    if ((px[y * w + x] >>> 24) > 40) { x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y); }
            if (x1 > x0 && y1 > y0) res = Bitmap.createBitmap(full, x0, y0, x1 - x0 + 1, y1 - y0 + 1);
        } catch (RuntimeException e) { /* без флага: рисуем код страны */ }
        flagBmp.put(cc, res);
        return res;
    }

    /** Кружок узла: эмодзи флага страны растянут на весь круг, кольцо - цвет из хеша узла (различает узлы одной страны). Своё эмодзи в имени - на цветной заливке. */
    private void drawBadge(Canvas c, Node n, float cx, float cy, float r, boolean dim) {
        int col = colorOf(n.dest.isEmpty() ? n.name : n.dest);
        String own = leadingEmoji(suffixOf(n.name).trim());
        Bitmap fb = own.isEmpty() && !n.cc.equals("XX") ? flagBitmap(n.cc) : null;
        p.setStyle(Paint.Style.FILL);
        if (fb != null) {
            Path clip = new Path();
            clip.addCircle(cx, cy, r, Path.Direction.CW);
            c.save();
            c.clipPath(clip);
            Paint bp = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);
            c.drawBitmap(fb, null, new RectF(cx - r, cy - r, cx + r, cy + r), bp);
            c.restore();
            p.setStyle(Paint.Style.STROKE);
            p.setStrokeWidth(4 * d);
            p.setColor(col);
            c.drawCircle(cx, cy, r - 2 * d, p);
            p.setStyle(Paint.Style.FILL);
        } else {
            p.setColor(col);
            c.drawCircle(cx, cy, r, p);
            String s = badgeOf(n.name, n.cc);
            boolean emoji = !own.isEmpty();
            // узел без страны, но с известным типом (телефон-админ, сервер без флага) - значок типа вместо «?»
            if (!emoji && "?".equals(s) && !kindIcon(n.pl).isEmpty()) { s = kindIcon(n.pl); emoji = true; }
            Paint b = new Paint(Paint.ANTI_ALIAS_FLAG);
            b.setTextAlign(Paint.Align.CENTER);
            b.setTextSize(r * (emoji ? 1.0f : 0.78f));
            b.setFakeBoldText(!emoji);
            b.setColor(0xFFFFFFFF);
            if (!emoji) b.setShadowLayer(2 * d, 0, 0, 0x99000000);
            Paint.FontMetrics m = b.getFontMetrics();
            c.drawText(s, cx, cy - (m.ascent + m.descent) / 2f, b);
        }
        if (dim) {
            p.setColor(Ui.dark(getContext()) ? 0x99000000 : 0x99FFFFFF);
            c.drawCircle(cx, cy, r, p);
        }
    }

    /** Значок типа узла (три типа): android и ios - телефон, server - сервер или приложение на компьютере; неизвестный - без значка. */
    static String kindIcon(String pl) {
        if (pl == null) return "";
        switch (pl) {
            case "android": case "ios": return "\uD83D\uDCF1";
            case "server": return "\uD83D\uDDA5";
            default: return "";
        }
    }

    /** Подпись под кружком: флаг и название страны; если в стране несколько узлов - добавляем имя узла. */
    static String labelOf(Node n, boolean twin) {
        String l;
        if (n.cc.equals("XX")) {
            // страна неизвестна (телефон-админ, узел без страны): имя показываем как есть, без «🌐 ?»
            l = plainName(n.name);
        } else {
            l = flagOf(n.cc) + " " + countryName(n.cc);
            String suf = suffixOf(n.name);
            if (twin) l = l + " " + (suf.length() > 9 ? suf.substring(0, 9) : suf);
        }
        String k = kindIcon(n.pl);
        return k.isEmpty() ? l : l + " " + k;
    }

    /** Имя без страны: не обрезаем до 12 символов - там имя телефона с хешем. */
    static String plainName(String name) {
        return name.length() > 18 ? name.substring(0, 18) : name;
    }

    // ------------------------------------------------------------------ рисование

    private Path curve(float x1, float y1, float x2, float y2, float bend) {
        float mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
        float dx = x2 - x1, dy = y2 - y1;
        Path q = new Path();
        q.moveTo(x1, y1);
        q.quadTo(mx - dy * bend, my + dx * bend, x2, y2);
        return q;
    }

    @Override
    protected void onDraw(Canvas c) {
        List<Node> ns;
        synchronized (nodes) { ns = new ArrayList<>(nodes); }
        float r = 24 * d;
        Node cur = null;
        for (Node n : ns) if ("current".equals(n.state)) cur = n;
        long nowF = System.nanoTime();
        float dtF = lastFrame == 0 ? 0.016f : Math.min(0.033f, (nowF - lastFrame) / 1e9f);
        lastFrame = nowF;
        float energy = 0;
        if (active) for (int sub = 0; sub < 2; sub++) energy += step(ns, dtF / 2);
        boolean animate = dragged || (energy > 20f * d * d && android.os.SystemClock.uptimeMillis() < settleUntil);
        if (!animate && energy > 20f * d * d) {
            // окно движения кончилось раньше покоя: гасим скорости, чтобы следующий кадр (обновление статуса) не дёргал узлы рывком
            for (float[] pa : phys.values()) { pa[2] = 0; pa[3] = 0; }
            phvx = phvy = 0;
        }
        float px = phx, py = phy;

        p.setStyle(Paint.Style.STROKE);
        t.setTextSize(10 * d);

        Node via = null;
        for (Node n : ns) if (n.isVia) via = n;
        Map<String, Node> byDest = new HashMap<>();
        for (Node n : ns) byDest.put(n.dest, n);
        // связи нода-нода из edges: тонкая прямая между двумя узлами графа, rtt мелко (нет узла - связь не рисуем)
        if (hasEdges) {
            p.setStrokeWidth(1f * d);
            p.setPathEffect(null);
            p.setColor(0x663478C6);
            t.setTextSize(8 * d);
            t.setColor(Ui.ink(getContext(), 0xFF3478C6));
            for (Edge e : edges) {
                Node na = byDest.get(e.a), nb = byDest.get(e.b);
                if (na == null || nb == null) continue;
                if (pingMode) {
                    p.setColor(pingColor(e.rtt, 0xAA));
                    p.setStrokeWidth((0.8f + 2.2f * (1 - pingNorm(e.rtt))) * d);
                }
                c.drawLine(na.x, na.y, nb.x, nb.y, p);
                if (e.rtt > 0) c.drawText(Math.round(e.rtt) + " мс", (na.x + nb.x) / 2, (na.y + nb.y) / 2 - 3 * d, t);
            }
            t.setTextSize(10 * d);
        }
        // связи текущего выхода с соседями по старой таблице: тонкие кривые (кроме транзитного: он нарисован как часть маршрута); только без edges
        if (!hasEdges && cur != null) {
            p.setStrokeWidth(1.5f * d);
            p.setPathEffect(null);
            for (Node n : ns) {
                if (n == cur || n == via || !"up".equals(n.state)) continue;
                p.setColor(0x883478C6);
                c.drawPath(curve(cur.x, cur.y, n.x, n.y, 0.22f), p);
                if (n.rtt > 0) {
                    t.setColor(Ui.ink(getContext(), 0xFF3478C6));
                    c.drawText("+" + Math.round(n.rtt) + " мс", (cur.x + n.x) / 2 + (n.y - cur.y) * 0.11f, (cur.y + n.y) / 2 - (n.x - cur.x) * 0.11f, t);
                }
            }
        }
        // узлы с путём RNS через транзит (vis via): подвешены тонкой пунктирной линией к своей nh, от телефона линии нет
        p.setStrokeWidth(1.2f * d);
        p.setPathEffect(new DashPathEffect(new float[]{5 * d, 5 * d}, 0));
        p.setColor(Ui.ink(getContext(), 0xFF6A6A70));
        for (Node n : ns) {
            if (!"via".equals(n.vis) || "current".equals(n.state) || n.nh.isEmpty() || n.nh.equals(n.dest)) continue;
            Node hop = byDest.get(n.nh);
            if (hop != null) c.drawLine(hop.x, hop.y, n.x, n.y, p);
        }
        p.setPathEffect(null);
        // телефон -> узел: сплошная по всему маршруту (через транзит или nh, если путь RNS через неё), пунктир к прямо видимым без трафика, нет линии при via и none
        for (Node n : ns) {
            boolean isCur = "current".equals(n.state);
            if (isCur) {
                p.setStrokeWidth(4.5f * d);
                p.setPathEffect(null);
                p.setColor(up ? 0xFF2E9E4F : 0xFFE0A100);
                Node hop = via;
                if ("via".equals(n.vis) && !n.nh.isEmpty() && !n.nh.equals(n.dest) && byDest.containsKey(n.nh)) hop = byDest.get(n.nh);
                if (hop != null) {
                    c.drawLine(px, py, hop.x, hop.y, p);
                    c.drawLine(hop.x, hop.y, n.x, n.y, p);
                    t.setColor(Ui.green(getContext()));
                    c.drawText("через " + shortName(hop.name), (hop.x + n.x) / 2, (hop.y + n.y) / 2 - 8 * d, t);
                    String s = ("tcp".equals(n.carrier) ? "TCP " : "") + (phoneRtt >= 0 ? Math.round(phoneRtt) + " мс" : "");
                    c.drawText(s, (px + hop.x) / 2, (py + hop.y) / 2 - 8 * d, t);
                } else if (!"via".equals(n.vis)) {
                    c.drawLine(px, py, n.x, n.y, p);
                    t.setColor(Ui.green(getContext()));
                    String s = ("tcp".equals(n.carrier) ? "TCP " : "") + (phoneRtt >= 0 ? Math.round(phoneRtt) + " мс" : "");
                    c.drawText(s, (px + n.x) / 2, (py + n.y) / 2 - 8 * d, t);
                }
            } else if ((n.vis.isEmpty() ? n.visible : "direct".equals(n.vis)) && !n.isVia && !"fail".equals(n.lk)) {   // пунктир только к узлам с прямым путём и возможным Link
                p.setStrokeWidth(2f * d);
                p.setPathEffect(new DashPathEffect(new float[]{9 * d, 7 * d}, 0));
                p.setColor(pingMode ? pingColor(n.rtt, 0xFF) : Ui.ink(getContext(), 0xFF6A6A70));
                if (pingMode) p.setStrokeWidth((1f + 2.5f * (1 - pingNorm(n.rtt))) * d);
                c.drawLine(px, py, n.x, n.y, p);
                if (pingMode && n.rtt > 0) {
                    t.setColor(Ui.ink(getContext(), 0xFF444444));
                    t.setTextSize(8.5f * d);
                    c.drawText(Math.round(n.rtt) + " мс", (px + n.x) / 2, (py + n.y) / 2 - 4 * d, t);
                    t.setTextSize(10 * d);
                }
                p.setPathEffect(null);
            }
        }
        p.setPathEffect(null);

        // телефон в центре: эмодзи телефона на круге состояния (зелёный - туннель поднят, серый - нет)
        p.setStyle(Paint.Style.FILL);
        p.setColor(up ? 0x332E9E4F : 0x228E8E93);
        c.drawCircle(px, py, 30 * d, p);
        p.setStyle(Paint.Style.STROKE);
        p.setStrokeWidth(2.5f * d);
        p.setColor(up ? 0xFF2E9E4F : 0xFF8E8E93);
        c.drawCircle(px, py, 30 * d, p);
        Paint ph = new Paint(Paint.ANTI_ALIAS_FLAG);
        ph.setTextAlign(Paint.Align.CENTER);
        ph.setTextSize(40 * d);
        Paint.FontMetrics fm = ph.getFontMetrics();
        c.drawText("\uD83D\uDCF1", px, py - (fm.ascent + fm.descent) / 2f, ph);
        t.setColor(Ui.ink(getContext(), 0xFF444444));
        t.setTextSize(10 * d);
        c.drawText(phoneLabel, px, py + 44 * d, t);

        // узлы
        for (Node n : ns) {
            boolean isCur = "current".equals(n.state);
            if (isCur) {
                p.setStyle(Paint.Style.STROKE);
                p.setStrokeWidth(4 * d);
                p.setColor(0x662E9E4F);
                c.drawCircle(n.x, n.y, r + 7 * d, p);
            }
            if (n.isVia) {
                p.setStyle(Paint.Style.STROKE);
                p.setStrokeWidth(3 * d);
                p.setColor(0x552E9E4F);
                c.drawCircle(n.x, n.y, r + 6 * d, p);
            }
            drawBadge(c, n, n.x, n.y, r, false);
            p.setStyle(Paint.Style.STROKE);
            p.setStrokeWidth((isCur ? 3 : 1.5f) * d);
            p.setColor(isCur || n.isVia ? Ui.green(getContext()) : Ui.ink(getContext(), 0xFF444444));
            c.drawCircle(n.x, n.y, r, p);
        }
        // Подписи поверх кружков и линий с подложкой под текущую тему.
        Paint h = new Paint(t);
        h.setStyle(Paint.Style.STROKE);
        h.setStrokeWidth(3.2f * d);
        h.setColor(Ui.dark(getContext()) ? 0xDD000000 : 0xDDFFFFFF);
        for (Node n : ns) {
            boolean isCur = "current".equals(n.state);
            int same = 0;
            for (Node o : ns) if (o.cc.equals(n.cc)) same++;
            String l1 = labelOf(n, same > 1);
            // Local reachability and neighbour observations are separate; neither missing data nor local failure means global death.
            String l2, l3 = null;
            if ("fail".equals(n.lk)) { l2 = "мой Link недоступен"; l3 = n.why; }
            else if ("none".equals(n.vis)) l2 = n.ra > 0 ? "видят другие узлы" : n.visible ? "носитель есть, пути нет" : "нет свежих данных";
            else if ("via".equals(n.vis)) { l2 = "через транзит"; if (n.hops >= 0) l3 = "путь RNS " + n.hops + " хоп"; }
            else if (n.isVia) l2 = "транзит";
            else if (n.visible) { l2 = "носитель " + carrierName(n.carrier); if (n.hops >= 0) l3 = "путь RNS " + n.hops + " хоп"; }
            else l2 = n.ra > 0 ? "видят другие узлы" : "нет свежих данных";
            t.setTextSize(11 * d); h.setTextSize(11 * d);
            h.setTextAlign(Paint.Align.CENTER);
            c.drawText(l1, n.x, n.y + r + 14 * d, h);
            t.setColor(isCur ? Ui.green(getContext()) : Ui.fg(getContext()));
            c.drawText(l1, n.x, n.y + r + 14 * d, t);
            t.setTextSize(9.5f * d); h.setTextSize(9.5f * d);
            c.drawText(l2, n.x, n.y + r + 26 * d, h);
            t.setColor(Ui.ink(getContext(), "fail".equals(n.lk) ? 0xFF999999 : 0xFF666666));
            c.drawText(l2, n.x, n.y + r + 26 * d, t);
            if (l3 != null && !l3.isEmpty()) {
                c.drawText(l3, n.x, n.y + r + 38 * d, h);
                c.drawText(l3, n.x, n.y + r + 38 * d, t);
            }
        }
        if (Util.LAB_BUILD && System.currentTimeMillis() - lastPosLog > 700 && !ns.isEmpty()) {   // для стенда: координаты узлов на экране
            lastPosLog = System.currentTimeMillis();
            int[] loc = new int[2];
            getLocationOnScreen(loc);
            StringBuilder b = new StringBuilder("phone=" + Math.round(loc[0] + phx) + "," + Math.round(loc[1] + phy) + " ");
            for (Node n : ns) b.append(n.name).append('=').append(Math.round(loc[0] + n.x)).append(',').append(Math.round(loc[1] + n.y)).append(' ');
            Util.lab("NODEPOS " + b);
            StringBuilder lk = new StringBuilder();   // для стенда: рёбра и состояние Link (status.json в обычной сборке не прочитать по adb)
            for (Node n : ns) lk.append(n.name).append(':').append(n.lk).append('/').append(n.vis.isEmpty() ? "-" : n.vis).append(n.why.isEmpty() ? "" : "(" + n.why + ")").append(' ');
            Util.lab("EDGES " + (hasEdges ? edges.size() : -1) + " lk " + lk);
        }
        if (ns.isEmpty()) {
            t.setColor(Ui.ink(getContext(), 0xFF888888));
            t.setTextSize(13 * d);
            c.drawText("ждём таблицу выходов…", px, py + 70 * d, t);
        }
        if (animate && active) postInvalidateDelayed(33); else lastFrame = 0;
    }

    // ------------------------------------------------------------------ жесты

    private Node hit(float x, float y) {
        Node best = null;
        float bd = (34 * d) * (34 * d);
        for (Node n : nodes) {
            float dx = x - n.x, dy = y - n.y, dd = dx * dx + dy * dy;
            if (dd < bd) { bd = dd; best = n; }
        }
        return best;
    }

    private boolean hitPhone(float x, float y) {
        float dx = x - phx, dy = y - phy;
        return dx * dx + dy * dy < (38 * d) * (38 * d);
    }

    /** Родитель (ScrollView) не перехватывает жест; view может быть уже отсоединён - тогда родителя нет. */
    private void disallowIntercept(boolean v) {
        android.view.ViewParent p = getParent();
        if (p != null) p.requestDisallowInterceptTouchEvent(v);
    }

    @Override
    public boolean onTouchEvent(MotionEvent e) {
        float x = e.getX(), y = e.getY();
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                disallowIntercept(true);  // ScrollView не должен перехватывать жест
                downX = x; downY = y; dragged = false;
                synchronized (nodes) { dragNode = hit(x, y); }
                dragPhone = dragNode == null && hitPhone(x, y);
                longPicked = false;
                if (dragNode != null || dragPhone) postDelayed(longPress, android.view.ViewConfiguration.getLongPressTimeout());
                return true;
            case MotionEvent.ACTION_MOVE: {
                float dx = x - downX, dy = y - downY;
                if (!dragged && dx * dx + dy * dy > (8 * d) * (8 * d)) dragged = true;
                if (dragged) removeCallbacks(longPress);
                if (!dragged) return true;
                // окно движения продлеваем только при настоящем перетаскивании: тап по узлу не должен
                // держать перерисовку 30 fps ещё 8 с
                settleUntil = android.os.SystemClock.uptimeMillis() + SETTLE_MS;
                float mx = Math.max(24 * d, Math.min(getWidth() - 24 * d, x)), my = Math.max(24 * d, Math.min(getHeight() - 24 * d, y));
                if (dragNode != null) {
                    float[] pa = phys.get(dragNode.dest);
                    if (pa != null) { pa[0] = mx; pa[1] = my; pa[2] = pa[3] = 0; }
                } else if (dragPhone) {
                    phx = mx; phy = my; phvx = phvy = 0;
                }
                invalidate();
                return true;
            }
            case MotionEvent.ACTION_UP: {
                disallowIntercept(false);
                boolean wasDrag = dragged;
                removeCallbacks(longPress);
                dragged = false;
                if (!wasDrag && !longPicked) {
                    Node n;
                    synchronized (nodes) { n = hit(x, y); }
                    if (n != null && onPick != null) {
                        Ui.tick(this);
                        onPick.pick(n.dest, n.name);
                    } else if (n == null && hitPhone(x, y)) {
                        if (onPhonePick != null) { Ui.tick(this); onPhonePick.run(); }
                    } else if (n == null) {
                        long now = System.currentTimeMillis();
                        if (now - lastTapMs < 350) {   // двойное касание: встряхнуть, всё возвращается на кольцо
                            phys.clear();
                            phx = cx(); phy = cy(); phvx = phvy = 0;
                        }
                        lastTapMs = now;
                    }
                }
                dragNode = null; dragPhone = false;
                invalidate();   // продолжить колебания после отпускания
                return true;
            }
            case MotionEvent.ACTION_CANCEL:
                disallowIntercept(false);
                removeCallbacks(longPress);
                dragged = false; dragNode = null; dragPhone = false;
                return true;
        }
        return super.onTouchEvent(e);
    }
}
