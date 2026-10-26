package com.knothop.vpn;

final class Native {
    static { System.loadLibrary("knothopmeas"); }
    /** knothopd client: блокирует до остановки (файл fin) или ошибки. 0 - штатно, иначе см. error.txt. */
    static native int runVpn(String args, String stateDir);
    /** Runs a bounded read/admin CLI command and returns its JSON result; never accepts secrets. */
    static native String runCLI(String command, String stateDir);
    /** Process-wide hint, retained by native even before the VPN runtime starts. */
    static native void setUiVisible(boolean visible);
    static native void networkChanged();
}
