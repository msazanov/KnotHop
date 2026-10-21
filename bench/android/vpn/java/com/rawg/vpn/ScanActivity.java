package com.rawg.vpn;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.Camera;
import android.os.Bundle;
import android.view.Gravity;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Сканер QR приглашения. Камера включается только на этом экране и только после нажатия «Сканировать QR» и разрешения пользователя;
 * кадры разбираются в памяти и не сохраняются и никуда не отправляются. Результат (текст QR) уходит вызвавшей активности и не пишется в журнал.
 */
public final class ScanActivity extends Activity implements SurfaceHolder.Callback, Camera.PreviewCallback {
    static final String EXTRA_TEXT = "text";
    private static final int REQ_CAMERA = 5;

    private Camera cam;
    private SurfaceView view;
    private boolean surface;
    private volatile boolean resumed;
    private final AtomicBoolean busy = new AtomicBoolean();
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private volatile boolean done;
    private final Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        FrameLayout root = new FrameLayout(this);
        view = new SurfaceView(this);
        view.getHolder().addCallback(this);
        root.addView(view, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        TextView hint = new TextView(this);
        hint.setText("Наведите камеру на QR приглашения");
        hint.setTextColor(0xFFFFFFFF);
        hint.setBackgroundColor(0x99000000);
        hint.setPadding(24, 24, 24, 24);
        root.addView(hint, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP));
        Button cancel = new Button(this);
        cancel.setText("Отмена");
        cancel.setOnClickListener(v -> finish());
        root.addView(cancel, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL));
        setContentView(root);
        if (checkSelfPermission("android.permission.CAMERA") != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.CAMERA"}, REQ_CAMERA);
        }
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] res) {
        if (req != REQ_CAMERA) return;
        if (res.length > 0 && res[0] == PackageManager.PERMISSION_GRANTED) {
            start();
        } else {
            Toast.makeText(this, "Без доступа к камере QR не считать: вставьте строку приглашения вручную", Toast.LENGTH_LONG).show();
            finish();
        }
    }

    @Override public void surfaceCreated(SurfaceHolder h) { surface = true; start(); }
    @Override public void surfaceChanged(SurfaceHolder h, int f, int w, int hh) { }
    @Override public void surfaceDestroyed(SurfaceHolder h) { surface = false; stop(); }

    @Override
    protected void onPause() {
        resumed = false;
        super.onPause();
        stop();
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        start();
    }

    @Override
    protected void onDestroy() {
        resumed = false;
        stop();
        super.onDestroy();
        worker.shutdownNow();
    }

    @SuppressWarnings("deprecation")
    private void start() {
        if (!resumed || isFinishing() || isDestroyed() || cam != null || !surface || done || checkSelfPermission("android.permission.CAMERA") != PackageManager.PERMISSION_GRANTED) return;
        try {
            cam = Camera.open();
            Camera.CameraInfo info = new Camera.CameraInfo();
            Camera.getCameraInfo(0, info);
            int deg = 0;
            switch (getWindowManager().getDefaultDisplay().getRotation()) {
                case Surface.ROTATION_90: deg = 90; break;
                case Surface.ROTATION_180: deg = 180; break;
                case Surface.ROTATION_270: deg = 270; break;
                default: break;
            }
            cam.setDisplayOrientation((info.orientation - deg + 360) % 360);
            Camera.Parameters p = cam.getParameters();
            Camera.Size best = null;
            for (Camera.Size s : p.getSupportedPreviewSizes()) {
                if (s.width <= 1280 && s.height <= 960 && (best == null || s.width * s.height > best.width * best.height)) best = s;
            }
            if (best != null) p.setPreviewSize(best.width, best.height);
            if (p.getSupportedFocusModes().contains(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE)) p.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE);
            cam.setParameters(p);
            cam.setPreviewDisplay(view.getHolder());
            cam.setPreviewCallback(this);
            cam.startPreview();
        } catch (Throwable e) {
            Toast.makeText(this, "Камера недоступна: вставьте строку приглашения вручную", Toast.LENGTH_LONG).show();
            stop();
            finish();
        }
    }

    @SuppressWarnings("deprecation")
    private void stop() {
        Camera c = cam;
        cam = null;
        if (c == null) return;
        try { c.setPreviewCallback(null); c.stopPreview(); } catch (Throwable ignored) { }
        c.release();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onPreviewFrame(byte[] data, Camera camera) {
        if (done || !busy.compareAndSet(false, true)) return;
        Camera.Size sz = camera.getParameters().getPreviewSize();
        final int w = sz.width, h = sz.height;
        try {
            worker.execute(() -> {
                try {
                    PlanarYUVLuminanceSource src = new PlanarYUVLuminanceSource(data, w, h, 0, 0, w, h, false);
                    QRCodeReader reader = new QRCodeReader();
                    Result r = reader.decode(new BinaryBitmap(new HybridBinarizer(src)), hints);
                    String t = r.getText();
                    if (t != null && (t.startsWith(Profile.LINK) || t.startsWith("rawgi-")) && !done) {
                        done = true;
                        runOnUiThread(() -> {
                            if (!resumed || isFinishing() || isDestroyed()) { done = false; return; }
                            setResult(RESULT_OK, new Intent().putExtra(EXTRA_TEXT, t));
                            finish();
                        });
                    }
                } catch (Throwable ignored) {
                    // в кадре нет читаемого QR - ждём следующий
                } finally {
                    busy.set(false);
                }
            });
        } catch (Throwable e) {
            busy.set(false);
        }
    }
}
