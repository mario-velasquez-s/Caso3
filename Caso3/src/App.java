//package app;

import servidor.ServidorPrincipal;
import cliente.Cliente;

import java.io.BufferedWriter;
import java.io.IOException;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import utils.MetricsCollector;


public class App {

    /* ------------------------------------------------------------------ */
    private static final int PUERTO = 5000;
    private static final int TIMEOUT_MS = 5_000;
    /* ------------------------------------------------------------------ */

    /* 0)  GENERAR LLAVES SI FALTAN  */
    private static void generarLlavesSiNoExisten() throws Exception {
        Path dir  = Paths.get("llaves");
        Path priv = dir.resolve("llave_privada_servidor.der");
        Path pub  = dir.resolve("llave_publica_servidor.der");

        if (Files.exists(priv) && Files.exists(pub)) return;

        Files.createDirectories(dir);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        Files.write(priv, kp.getPrivate().getEncoded());
        Files.write(pub,  kp.getPublic().getEncoded());
        System.out.println("[App] Llaves RSA generadas automáticamente.");
    }

    /* 1)  ¿PUERTO LIBRE?  */
    private static boolean puertoLibre(int puerto) {
        try (ServerSocket ss = new ServerSocket(puerto)) { return true; }
        catch (IOException e) { return false; }
    }

    /* 2)  LANZAR SERVIDOR SOLO SI EL PUERTO ESTÁ LIBRE */
    private static void asegurarServidorLevantado() throws Exception {

        if (!puertoLibre(PUERTO)) {
            System.out.println("[App] Puerto " + PUERTO +
                               " ya ocupado. Se asume que el servidor está activo.");
            return;                       
        }

        System.out.println("=== Iniciando servidor …");
        Thread t = new Thread(() -> {
            try { ServidorPrincipal.main(null); }
            catch (Exception e) { System.err.println("[App] Servidor abortó: " + e); }
        }, "ServidorPrincipal");
        t.setDaemon(true);
        t.start();

        esperarPuertoAbierto(PUERTO, TIMEOUT_MS);
    }

    /* 3)  ESPERAR PUERTO LISTENING */
    private static void esperarPuertoAbierto(int puerto, int timeoutMs) throws Exception {
        long ini = System.currentTimeMillis();
        while (System.currentTimeMillis() - ini < timeoutMs) {
            try (Socket s = new Socket("localhost", puerto)) { return; }
            catch (ConnectException e) { Thread.sleep(100); }
        }
        throw new IllegalStateException("Servidor no abrió el puerto en " + timeoutMs + " ms");
    }

    /* 4)  BENCHMARK  */
    private static void correrBenchmark() throws Exception {

        int[] hilos = {1,4,16,32,64};
        int[] reps  = {32,1,1,1,1};
    
        Files.createDirectories(Path.of("bench"));
        try(BufferedWriter bw=Files.newBufferedWriter(Path.of("bench","resultados.csv"))){
    
            bw.write("hilos,reps,ms_prom\n");
    
            for(int k=0;k<hilos.length;k++){
                int nH=hilos[k], r=reps[k];
    
                /* marcar escenario */
                String esc=(nH==1)?"iterativo-32":"concurrent-"+nH;
                MetricsCollector.setEscenario(esc);            
    
                ExecutorService pool=Executors.newFixedThreadPool(nH);
                List<Future<Long>> fut=new ArrayList<>();
                for(int h=0;h<nH;h++)
                    fut.add(pool.submit(new cliente.Cliente((h%3)+1,r)));
                pool.shutdown(); pool.awaitTermination(10,TimeUnit.MINUTES);
    
                long tot=0; for(Future<Long> f:fut) tot+=f.get();
                double ms=(tot/(double)(nH*r))/1e6;
                System.out.printf(" %2d hilos × %2d rep → %.3f ms%n",nH,r,ms);
                bw.write(String.format("%d,%d,%.4f%n",nH,r,ms));
            }
        }
    
        /* volcar CSVs de métricas */
        MetricsCollector.dumpCSVs(); 
    }

    /* 5)  FLUJO AUTOMÁTICO (sin args) */
    private static void flujoAutomatico() {
        try {
            generarLlavesSiNoExisten();
            asegurarServidorLevantado();
            System.out.println("=== Corriendo benchmark …");
            correrBenchmark();
            System.out.println("=== Fin automático ✔");
        } catch (Exception e) {
            System.err.println("[App-auto] " + e.getMessage());
        }
    }

    /* 6)  MAIN (modos manuales opcionales)  */
    public static void main(String[] args) throws Exception {

        if (args.length == 0) {          
            flujoAutomatico();
            return;
        }

        switch (args[0].toLowerCase()) {
            case "server" -> {
                generarLlavesSiNoExisten();
                asegurarServidorLevantado();
            }
            case "client" -> {
                if (args.length == 3)
                    Cliente.main(Arrays.copyOfRange(args, 1, 3));
                else
                    Cliente.main(new String[0]);
            }
            case "bench"  -> correrBenchmark();
            default -> System.err.println("""
                     Comandos:
                       (sin args)         flujo automático
                       server             inicia servidor (si no está)
                       client             cliente interactivo
                       client <id> <rep>  cliente silencioso
                       bench              benchmark (requiere servidor)
                     """);
        }
    }
}
