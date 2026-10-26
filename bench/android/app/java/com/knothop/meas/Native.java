package com.knothop.meas;

final class Native {
    static { System.loadLibrary("knothopmeas"); }
    /** Блокирует до конца замера. 0 - готово, иначе см. error.txt в каталоге состояния. */
    static native int run(String args, String stateDir);
}
