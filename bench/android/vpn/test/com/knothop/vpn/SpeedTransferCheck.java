package com.knothop.vpn;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.HttpURLConnection;
import java.util.concurrent.atomic.AtomicLong;

/** Local HTTP only: no device, public endpoints or VPN connectivity claimed. */
public final class SpeedTransferCheck {
    private static void require(boolean ok) { if (!ok) throw new AssertionError(); }
    private static void reject(RunnableTest test) throws Exception {
        try { test.run(); throw new AssertionError("accepted"); }
        catch (java.io.IOException expected) { }
    }
    interface RunnableTest { void run() throws Exception; }

    public static void main(String[] args) throws Exception {
        AtomicLong uploaded = new AtomicLong();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/down", exchange -> {
            byte[] body = new byte[8192];
            exchange.sendResponseHeaders(200, body.length);
            try (java.io.OutputStream out = exchange.getResponseBody()) { out.write(body); }
        });
        server.createContext("/up", exchange -> {
            long n = 0;
            byte[] body = new byte[1024];
            try (java.io.InputStream in = exchange.getRequestBody()) {
                int read; while ((read = in.read(body)) >= 0) n += read;
            }
            uploaded.set(n);
            exchange.sendResponseHeaders(200, -1); exchange.close();
        });
        server.createContext("/error", exchange -> { exchange.sendResponseHeaders(503, -1); exchange.close(); });
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", "/down");
            exchange.sendResponseHeaders(302, -1); exchange.close();
        });
        server.createContext("/slow", exchange -> {
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            try { exchange.sendResponseHeaders(200, -1); } finally { exchange.close(); }
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        SpeedTransfer.Connection plain = url -> (HttpURLConnection)url.openConnection();
        try {
            SpeedTransfer.Result down = SpeedTransfer.run(plain, () -> true, base + "/down", false, 2048, 2000);
            require(down.bytes == 2048 && down.limited && down.nanos > 0 && down.text().contains("Мбит/с"));
            SpeedTransfer.Result up = SpeedTransfer.run(plain, () -> true, base + "/up", true, 4096, 2000);
            require(up.bytes == 4096 && uploaded.get() == 4096);
            reject(() -> SpeedTransfer.run(plain, () -> false, base + "/down", false, 2048, 2000));
            reject(() -> SpeedTransfer.run(plain, () -> true, base + "/down", false, SpeedTransfer.MAX_BYTES + 1, 2000));
            reject(() -> SpeedTransfer.run(plain, () -> true, base + "/down", false, 2048, SpeedTransfer.MAX_MS + 1));
            reject(() -> SpeedTransfer.run(plain, () -> true, base + "/error", false, 2048, 2000));
            reject(() -> SpeedTransfer.run(plain, () -> true, base + "/redirect", false, 2048, 2000));
            long start = System.nanoTime();
            reject(() -> SpeedTransfer.run(plain, () -> true, base + "/slow", false, 2048, 100));
            require(System.nanoTime() - start < 2_000_000_000L);
            reject(() -> SpeedTransfer.endpoint("http://user:secret@host/path", 10));
            reject(() -> SpeedTransfer.endpoint("file:/etc/passwd", 10));
            require(SpeedTransfer.endpoint(SpeedTransfer.DOWN, 42).getQuery().equals("bytes=42"));
            System.out.println("SpeedTransferCheck PASS (volume, upload ACK, VPN guard, volume/time limits, HTTP errors, redirects, URL)");
        } finally { server.stop(0); }
    }
}
