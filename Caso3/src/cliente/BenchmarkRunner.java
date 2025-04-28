package cliente;

import utils.MetricsCollector;
import java.util.concurrent.*;
import java.util.*;

public class BenchmarkRunner {

    private static final int[] LOTES = {1,4,16,32,64};
    private static final int[] REPS  = {32,1,1,1,1};

    public static void main(String[] a) throws Exception {

        java.nio.file.Files.createDirectories(java.nio.file.Path.of("bench"));
        try(var bw=java.nio.file.Files.newBufferedWriter(
                     java.nio.file.Path.of("bench","resultados.csv"))){

            bw.write("hilos,reps,ms_prom\n");

            for(int k=0;k<LOTES.length;k++){

                int n=LOTES[k], r=REPS[k];
                MetricsCollector.setEscenario(n==1?"iterativo-32":"concurrent-"+n); 

                ExecutorService pool=Executors.newFixedThreadPool(n);
                List<Future<Long>> fs=new ArrayList<>();
                for(int h=0;h<n;h++) fs.add(pool.submit(new Cliente((h%3)+1,r)));
                pool.shutdown(); pool.awaitTermination(10,TimeUnit.MINUTES);

                long tot=0; for(Future<Long> f:fs) tot+=f.get();
                double ms=(tot/(double)(n*r))/1e6;
                System.out.printf(">> %2d×%2d → %.3f ms%n",n,r,ms);
                bw.write(String.format("%d,%d,%.4f%n",n,r,ms));
            }
        }
        MetricsCollector.dumpCSVs();                                 
    }
}
