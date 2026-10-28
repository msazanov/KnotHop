package com.knothop.vpn;

public final class GraphColorsCheck {
    private static double channel(int n) { double v=n/255.0; return v<=0.04045?v/12.92:Math.pow((v+0.055)/1.055,2.4); }
    private static void check(int c) {
        double l=0.2126*channel(c>>16&255)+0.7152*channel(c>>8&255)+0.0722*channel(c&255);
        if ((c>>>24)!=255 || (l+0.05)/0.05<4.5) throw new AssertionError("insufficient contrast on black: "+Integer.toHexString(c));
    }
    public static void main(String[] args) {
        check(GraphColors.mesh(true)); check(GraphColors.active(true)); check(GraphColors.extra(true)); check(GraphColors.idle(true));
        check(GraphColors.ping(true,0xFF3CAA28)); check(GraphColors.ping(true,0xFFF03228));
        System.out.println("GraphColorsCheck PASS (black-background contrast >= 4.5:1)");
    }
}
