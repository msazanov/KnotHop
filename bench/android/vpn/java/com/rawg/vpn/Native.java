package com.rawg.vpn;

final class Native {
    static { System.loadLibrary("rawgmeas"); }
    /** rawgd client: блокирует до остановки (файл fin) или ошибки. 0 - штатно, иначе см. error.txt. */
    static native int runVpn(String args, String stateDir);
    /** Process-wide hint, retained by native even before the VPN runtime starts. */
    static native void setUiVisible(boolean visible);
    static native void networkChanged();
    /** Приглашение (rawgi-… или эмодзи) -> эмодзи, самая короткая текстовая форма; пустая строка - не приглашение. */
    static native String toEmoji(String invite);
    /** Приглашение (rawgi-… или эмодзи) -> каноническая rawgi-…; пустая строка - не приглашение. */
    static native String toBase64(String invite);
}
