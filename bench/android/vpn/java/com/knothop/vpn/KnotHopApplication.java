package com.knothop.vpn;

import android.app.Activity;
import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/** Visibility is only a diagnostic hint; it never starts or stops the VPN. */
public final class KnotHopApplication extends Application implements Application.ActivityLifecycleCallbacks {
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Set<Activity> started = Collections.newSetFromMap(new IdentityHashMap<Activity, Boolean>());
    private final Set<Activity> resumed = Collections.newSetFromMap(new IdentityHashMap<Activity, Boolean>());
    private PowerManager power;
    private boolean visible;
    private final Runnable background = () -> publish(false);

    @Override public void onCreate() {
        super.onCreate();
        Util.init(this);
        power = (PowerManager) getSystemService(POWER_SERVICE);
        Native.setUiVisible(false); // Initializes the hint before a native runtime exists.
        registerActivityLifecycleCallbacks(this);
        BroadcastReceiver screen = new BroadcastReceiver() {
            @Override public void onReceive(Context c, Intent i) {
                if (Intent.ACTION_SCREEN_OFF.equals(i.getAction())) {
                    ui.removeCallbacks(background);
                    publish(false);
                } else updateVisibility();
            }
        };
        IntentFilter filter = new IntentFilter(Intent.ACTION_SCREEN_OFF);
        filter.addAction(Intent.ACTION_SCREEN_ON);
        filter.addAction(Intent.ACTION_USER_PRESENT);
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(screen, filter, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(screen, filter);
    }

    private void publish(boolean value) {
        if (visible == value) return;
        visible = value;
        Native.setUiVisible(value);
    }

    private void updateVisibility() {
        ui.removeCallbacks(background);
        if (power != null && !power.isInteractive()) publish(false);
        else if (!started.isEmpty() && !resumed.isEmpty()) publish(true);
        else ui.postDelayed(background, 400); // Bridge Activity transitions/configuration changes.
    }

    @Override public void onActivityStarted(Activity a) { started.add(a); updateVisibility(); }
    @Override public void onActivityResumed(Activity a) { resumed.add(a); updateVisibility(); }
    @Override public void onActivityPaused(Activity a) { resumed.remove(a); updateVisibility(); }
    @Override public void onActivityStopped(Activity a) { started.remove(a); resumed.remove(a); updateVisibility(); }
    @Override public void onActivityDestroyed(Activity a) { started.remove(a); resumed.remove(a); updateVisibility(); }
    @Override public void onActivityCreated(Activity a, Bundle b) { }
    @Override public void onActivitySaveInstanceState(Activity a, Bundle b) { }
}
