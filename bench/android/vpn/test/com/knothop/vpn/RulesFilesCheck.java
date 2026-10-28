package com.knothop.vpn;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.io.File;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicInteger;

/** Изолированный HTTP fixture: загрузка, идемпотентное обновление и сохранение прежних файлов при ошибке checksum. */
public final class RulesFilesCheck {
    private static void check(boolean ok,String why) { if (!ok) throw new AssertionError(why); }
    public static void main(String[] args) throws Exception {
        byte[] data = new byte[32768]; for (int i=0;i<data.length;i++) data[i]=(byte)i;
        StringBuilder hex=new StringBuilder(); for(byte b:MessageDigest.getInstance("SHA-256").digest(data)) hex.append(String.format("%02x",b));
        AtomicInteger downloads=new AtomicInteger(), mode=new AtomicInteger();
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/",e->{
            boolean sum=e.getRequestURI().getPath().endsWith(".sha256sum");
            if(sum && mode.get()==1){e.sendResponseHeaders(404,-1);e.close();return;}
            byte[] body=sum?((mode.get()==2?"00".repeat(32):hex.toString())+" file").getBytes():data;
            if(!sum)downloads.incrementAndGet();
            e.sendResponseHeaders(200,body.length);try(var out=e.getResponseBody()){out.write(body);}
        });
        server.start();
        try {
            File dir=Files.createTempDirectory("kh-geo-refresh-").toFile();
            String[] bases={"http://127.0.0.1:"+server.getAddress().getPort()+"/"};
            check(RulesFiles.download(dir,t->{},bases).isEmpty() && RulesFiles.present(dir),"first refresh downloads absent files");
            check(downloads.get()==2,"two files initially");
            check(RulesFiles.download(dir,t->{},bases).isEmpty() && downloads.get()==2,"unchanged hashes download zero dataset bytes");
            File geo=new File(RulesFiles.dir(dir),"geoip.dat");Files.writeString(geo.toPath(),"damaged");
            check(RulesFiles.download(dir,t->{},bases).isEmpty() && downloads.get()==3,"repair only the damaged file");
            byte[] previous=Files.readAllBytes(geo.toPath());
            mode.set(1);check(!RulesFiles.download(dir,t->{},bases).isEmpty(),"missing checksum is not success");
            check(java.util.Arrays.equals(previous,Files.readAllBytes(geo.toPath())),"preserve old file without checksum");
            mode.set(2);check(!RulesFiles.download(dir,t->{},bases).isEmpty(),"checksum mismatch rejected");
            check(java.util.Arrays.equals(previous,Files.readAllBytes(geo.toPath())),"preserve old file on mismatch");
            check(!new File(RulesFiles.dir(dir),"geoip.dat.part").exists(),"partial file cleaned");
            System.out.println("RulesFilesCheck PASS (first refresh 65536 payload bytes; unchanged refresh 0 dataset bytes)");
        } finally {server.stop(0);}
    }
}
