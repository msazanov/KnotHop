package com.rawg.meas;

final class Native {
    static { System.loadLibrary("rawgmeas"); }
    /** Блокирует до конца замера. 0 - готово, иначе см. error.txt в каталоге состояния. */
    static native int run(String args, String stateDir);
}
