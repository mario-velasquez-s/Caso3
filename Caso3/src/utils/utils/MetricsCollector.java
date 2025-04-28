package utils;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.io.BufferedWriter; 

/**
 *  Recolector de métricas de cripto-operaciones.
 *
 *  •  Delegado.log(…) añade un registro por consulta.
 *  •  setEscenario() lo invocan App / BenchmarkRunner antes de cada lote.
 *  •  dumpCSVs() genera:
 *        bench/op_registro.csv   – datos crudos
 *        bench/op_promedios.csv  – promedios por escenario
 */
public final class MetricsCollector {

    private MetricsCollector() {}

    /* ---- escenario actual ---- */
    private static final AtomicReference<String> escenario =
            new AtomicReference<>("undefined");

    public static void setEscenario(String esc) { escenario.set(esc); }

    /* ---- registro ---- */
    public static final class Rec {
        public final String esc;
        public final long   sign, cifTabla, verif,
                            cifRespSym, cifRespAsim;
        Rec(String e,long s,long t,long v,long sym,long asym){
            esc=e; sign=s; cifTabla=t; verif=v; cifRespSym=sym; cifRespAsim=asym;
        }
    }
    private static final List<Rec> registros =
            Collections.synchronizedList(new ArrayList<>());

    public static void log(long tSign,long tCifTab,long tVer,
                           long tSym,long tAsym){
        registros.add(new Rec(escenario.get(),tSign,tCifTab,tVer,tSym,tAsym));
    }

    /* ========= CSVs ========= */
    private static final class Agg {           // ← reemplaza al record
        long n,s,c,v,sym,asym;
        void add(Rec r){
            n++; s+=r.sign; c+=r.cifTabla; v+=r.verif;
            sym+=r.cifRespSym; asym+=r.cifRespAsim;
        }
    }

    public static void dumpCSVs() throws Exception {

        Files.createDirectories(Path.of("bench"));

        /* 1. crudo */
        try(BufferedWriter w=
                Files.newBufferedWriter(Path.of("bench","op_registro.csv"))){
            w.write("escenario,sign_ns,cifTabla_ns,verif_ns,cifRespSym_ns,cifRespAsim_ns\n");
            for(Rec r:registros)
                w.write(String.format("%s,%d,%d,%d,%d,%d%n",
                        r.esc,r.sign,r.cifTabla,r.verif,r.cifRespSym,r.cifRespAsim));
        }

        /* 2. promedios */
        Map<String,Agg> map=new HashMap<>();
        for(Rec r:registros) map.computeIfAbsent(r.esc,k->new Agg()).add(r);

        try(BufferedWriter w=
                Files.newBufferedWriter(Path.of("bench","op_promedios.csv"))){
            w.write("escenario,n,sign_ms,cifTabla_ms,verif_ms,cifRespSym_ms,cifRespAsim_ms\n");
            for(var e:map.entrySet()){
                Agg a=e.getValue(); double n=a.n;
                w.write(String.format(Locale.US,
                    "%s,%d,%.4f,%.4f,%.4f,%.4f,%.4f%n",
                    e.getKey(),a.n,
                    a.s   /1e6/n,
                    a.c   /1e6/n,
                    a.v   /1e6/n,
                    a.sym /1e6/n,
                    a.asym/1e6/n));
            }
        }
        System.out.println("[Metrics] CSVs generados en bench/");
    }
}
