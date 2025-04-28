package utils;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.security.*;
import java.security.spec.*;

public final class DHUtils {

    private DHUtils(){}

    private static final short MAGIC = (short)0xCAFE;

    /* parámetros DH comunes (2048 bits) */
    private static final DHParameterSpec SPEC;
    static{
        try{
            AlgorithmParameterGenerator g=AlgorithmParameterGenerator.getInstance("DH");
            g.init(2048);
            AlgorithmParameters p=g.generateParameters();
            SPEC=p.getParameterSpec(DHParameterSpec.class);
        }catch(Exception e){ throw new ExceptionInInitializerError(e); }
    }
    private static KeyPair nuevoPar() throws Exception{
        KeyPairGenerator kpg=KeyPairGenerator.getInstance("DH");
        kpg.initialize(SPEC); return kpg.generateKeyPair();
    }

    /* ---------------- servidor ---------------- */
    public static KeyAgreement acuerdoServidor(DataInputStream in,
                                               DataOutputStream out,
                                               KeyPair parSrv) throws Exception{

        byte[] pubS=parSrv.getPublic().getEncoded();
        out.writeShort(MAGIC); out.writeInt(pubS.length); out.write(pubS); out.flush();

        if(in.readShort()!=MAGIC) throw new IOException("MAGIC inesperado");
        int n=in.readInt(); byte[] pubC=new byte[n]; in.readFully(pubC);

        PublicKey cliPub=KeyFactory.getInstance("DH")
                         .generatePublic(new X509EncodedKeySpec(pubC));

        KeyAgreement ka=KeyAgreement.getInstance("DH");
        ka.init(parSrv.getPrivate()); ka.doPhase(cliPub,true);
        return ka;
    }

    /* ---------------- cliente ---------------- */
    public static KeyAgreement acuerdoCliente(DataInputStream in,
                                              DataOutputStream out) throws Exception{

        if(in.readShort()!=MAGIC) throw new IOException("MAGIC inesperado");
        int n=in.readInt(); byte[] pubS=new byte[n]; in.readFully(pubS);
        PublicKey srvPub=KeyFactory.getInstance("DH")
                         .generatePublic(new X509EncodedKeySpec(pubS));

        KeyPair parCli=nuevoPar();
        byte[] pubC=parCli.getPublic().getEncoded();
        out.writeShort(MAGIC); out.writeInt(pubC.length); out.write(pubC); out.flush();

        KeyAgreement ka=KeyAgreement.getInstance("DH");
        ka.init(parCli.getPrivate()); ka.doPhase(srvPub,true);
        return ka;
    }
}
