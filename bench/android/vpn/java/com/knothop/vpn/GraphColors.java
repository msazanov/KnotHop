package com.knothop.vpn;

/** Читаемые цвета рёбер, без зависимости от Android — контраст проверяется JVM-тестом. */
final class GraphColors {
    static int mesh(boolean dark) { return dark ? 0xFF8AB8FF : 0xCC3478C6; }
    static int active(boolean dark) { return dark ? 0xFF5FD38A : 0xFF237B43; }
    static int extra(boolean dark) { return dark ? 0xFFC5ADFF : 0xFF7544BA; }
    static int idle(boolean dark) { return dark ? 0xFFB8BEC7 : 0xFF6A6A70; }
    static int ping(boolean dark, int color) {
        if (!dark) return color;
        int r = color >> 16 & 255, g = color >> 8 & 255, b = color & 255;
        return 0xFF000000 | (r + (255-r)/3) << 16 | (g + (255-g)/3) << 8 | (b + (255-b)/3);
    }
}
