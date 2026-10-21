package com.rawg.meas;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Тестовое приложение замеров (НЕ клиент VPN): телефон <-> ноутбук по Wi-Fi через тракт rawg
 * (RNS Link-датаграммы поверх QUIC DATAGRAM). Адреса зашиты; IP ноутбука можно поправить в поле.
 * Ноутбук: bench/android/laptop.py (выход E, раздача e.json и приём результата по HTTP).
 */
public class MainActivity extends Activity {
    static final String DEFAULT_LAPTOP = "192.168.31.239";
    static final int HTTP_PORT = 8081;
    static final int QUIC_PORT = 47001;

    private TextView out;
    private Button start;
    private EditText ipField;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean running;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 48, 24, 24);

        TextView title = new TextView(this);
        title.setText("rawg: замер телефон <-> ноутбук (тест, не VPN)");
        title.setTextSize(16);
        root.addView(title);

        SharedPreferences sp = getSharedPreferences("p", MODE_PRIVATE);
        ipField = new EditText(this);
        ipField.setSingleLine(true);
        ipField.setText(sp.getString("ip", DEFAULT_LAPTOP));
        root.addView(ipField);

        start = new Button(this);
        start.setText("Старт замера");
        start.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                startRun();
            }
        });
        root.addView(start);

        out = new TextView(this);
        out.setTextSize(11);
        out.setTypeface(android.graphics.Typeface.MONOSPACE);
        out.setGravity(Gravity.TOP);
        out.setMovementMethod(new ScrollingMovementMethod());
        out.setText("Ноутбук: python3 bench/android/laptop.py\nПотом «Старт замера» (около 3 минут, экран не гасить).\n");
        root.addView(out, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);
    }

    private void show(final String s) {
        ui.post(new Runnable() {
            public void run() {
                out.setText(s);
                int lines = out.getLineCount();
                int h = out.getHeight();
                int lh = out.getLineHeight();
                int y = lines * lh - h;
                if (y > 0) out.scrollTo(0, y);
            }
        });
    }

    private void startRun() {
        if (running) return;
        running = true;
        start.setEnabled(false);
        final String ip = ipField.getText().toString().trim();
        getSharedPreferences("p", MODE_PRIVATE).edit().putString("ip", ip).apply();
        new Thread(new Runnable() {
            public void run() {
                try {
                    runTest(ip);
                } catch (Throwable t) {
                    show("Сбой: " + t);
                } finally {
                    running = false;
                    ui.post(new Runnable() {
                        public void run() {
                            start.setEnabled(true);
                        }
                    });
                }
            }
        }).start();
    }

    private JSONObject wifi() {
        JSONObject j = new JSONObject();
        try {
            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            WifiInfo i = wm.getConnectionInfo();
            j.put("rssi_dbm", i.getRssi());
            j.put("link_speed_mbps", i.getLinkSpeed());
            j.put("tx_link_speed_mbps", i.getTxLinkSpeedMbps());
            j.put("rx_link_speed_mbps", i.getRxLinkSpeedMbps());
            j.put("frequency_mhz", i.getFrequency());
            j.put("standard", Build.VERSION.SDK_INT >= 30 ? i.getWifiStandard() : -1);
        } catch (Throwable t) {
            try { j.put("error", t.toString()); } catch (Exception ignored) { }
        }
        return j;
    }

    private JSONObject device() throws Exception {
        JSONObject d = new JSONObject();
        d.put("manufacturer", Build.MANUFACTURER);
        d.put("model", Build.MODEL);
        d.put("sdk", Build.VERSION.SDK_INT);
        d.put("release", Build.VERSION.RELEASE);
        d.put("abi", Build.SUPPORTED_ABIS[0]);
        d.put("cores", Runtime.getRuntime().availableProcessors());
        if (Build.VERSION.SDK_INT >= 31) d.put("soc", Build.SOC_MANUFACTURER + " " + Build.SOC_MODEL);
        d.put("hardware", Build.HARDWARE);
        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        d.put("power_save", pm.isPowerSaveMode());
        return d;
    }

    private static String httpGet(String u) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(u).openConnection();
        c.setConnectTimeout(5000);
        c.setReadTimeout(8000);
        try (InputStream in = c.getInputStream()) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return bo.toString("UTF-8");
        }
    }

    private static void httpPost(String u, String body) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(u).openConnection();
        c.setConnectTimeout(5000);
        c.setReadTimeout(15000);
        c.setDoOutput(true);
        c.setRequestMethod("POST");
        c.setRequestProperty("Content-Type", "application/json");
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        c.setFixedLengthStreamingMode(b.length);
        try (OutputStream o = c.getOutputStream()) {
            o.write(b);
        }
        c.getResponseCode();
        c.disconnect();
    }

    private static String read(File f) {
        try {
            return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    private void runTest(String laptop) throws Exception {
        File state = new File(getFilesDir(), "state");
        state.mkdirs();
        for (File f : state.listFiles()) {
            if (f.isFile()) f.delete();
        }
        JSONObject report = new JSONObject();
        report.put("device", device());
        report.put("laptop", laptop);
        StringBuilder head = new StringBuilder();
        head.append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append(", Android ").append(Build.VERSION.RELEASE).append('\n');

        WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        WifiManager.WifiLock lock = null;
        if (Build.VERSION.SDK_INT >= 29) {
            lock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_LOW_LATENCY, "rawgmeas");
            lock.acquire();
        }
        try {
            JSONObject w0 = wifi();
            report.put("wifi_before", w0);
            head.append("Wi-Fi: ").append(w0.toString()).append('\n');
            show(head + "забираю параметры выхода с ноутбука...\n");
            String e;
            try {
                e = httpGet("http://" + laptop + ":" + HTTP_PORT + "/e.json");
            } catch (Exception ex) {
                show(head + "Не вижу ноутбук по http://" + laptop + ":" + HTTP_PORT + "/e.json\n" + ex
                        + "\nПроверь: laptop.py запущен, телефон в той же Wi-Fi сети, IP верный.");
                return;
            }
            Files.write(new File(state, "e.json").toPath(), e.getBytes(StandardCharsets.UTF_8));

            final String args = "--role c --ip 127.0.0.1 --dial e --relay none --mode meas --carrier datagram --dgram-mtu 1400 "
                    + "--cipher gcm --data-cap 4096 --chan-buf 4096 --quic-initial-mtu 1452 --quic-cc tunnel --quic-cc-mbit 500 "
                    + "--state " + state.getAbsolutePath();
            final int[] rc = {-1};
            final long cpu0 = android.os.Process.getElapsedCpuTime();
            Thread nt = new Thread(new Runnable() {
                public void run() {
                    rc[0] = Native.run(args, args.substring(args.lastIndexOf(' ') + 1));
                }
            });
            nt.start();
            File prog = new File(state, "progress.txt");
            while (nt.isAlive()) {
                show(head + "\n" + read(prog));
                Thread.sleep(500);
            }
            long cpuMs = android.os.Process.getElapsedCpuTime() - cpu0;
            String progress = read(prog);
            String result = read(new File(state, "result-c.json"));
            String error = read(new File(state, "error.txt"));
            JSONObject w1 = wifi();
            report.put("wifi_after", w1);
            report.put("rc", rc[0]);
            report.put("app_cpu_ms", cpuMs);
            report.put("progress", progress);
            report.put("error", error);
            String nlog = read(new File(state, "log.txt"));
            report.put("native_log", nlog);
            if (!result.isEmpty()) report.put("result", new JSONObject(result));
            String posted;
            try {
                httpPost("http://" + laptop + ":" + HTTP_PORT + "/result", report.toString());
                posted = "результат отправлен на ноутбук";
            } catch (Exception ex) {
                posted = "результат НЕ отправлен: " + ex;
            }
            String tail = "";
            if (!error.isEmpty()) tail += "\nОШИБКА: " + error + "\n" + (nlog.length() > 1500 ? nlog.substring(nlog.length() - 1500) : nlog) + "\n";
            show(head + "\n" + progress + tail + "\nWi-Fi после: " + w1 + "\n" + posted + "\n");
        } finally {
            if (lock != null && lock.isHeld()) lock.release();
        }
    }
}
