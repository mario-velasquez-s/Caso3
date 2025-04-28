package cliente;

import utils.*;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;
import java.util.concurrent.Callable;

public class Cliente implements Callable<Long> {

    private static final String HOST = "localhost";
    private static final int    PORT = 5000;
    private static final String PUB  = "llaves/llave_publica_servidor.der";

    private final int idServ, reps; private final boolean silent;

    public Cliente()                  { idServ=-1; reps=1;  silent=false; }
    public Cliente(int id,int r)      { idServ=id; reps=r; silent=true;  }

    
    private static SecretKey[] derive(byte[] secret) throws Exception {
        byte[] d=MessageDigest.getInstance("SHA-512").digest(secret);
        return new SecretKey[]{
            new SecretKeySpec(Arrays.copyOfRange(d,0,32),"AES"),
            new SecretKeySpec(Arrays.copyOfRange(d,32,64),"HmacSHA256")};
    }
    private static byte[] readBlock(DataInputStream in) throws IOException{
        int n=in.readInt(); byte[] b=new byte[n]; in.readFully(b); return b;}

    /* Consulta */
    private long round(int id) throws Exception {
        long t0=System.nanoTime();
        try(Socket s=new Socket(HOST,PORT)){
            s.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out= new DataOutputStream(s.getOutputStream());

            /* 1-2 HELLO + reto */
            out.writeUTF("HELLO");
            byte[] reto=new byte[16]; new SecureRandom().nextBytes(reto);
            out.writeInt(reto.length); out.write(reto);

            /* 3 ver firma */
            byte[] sig=readBlock(in);
            byte[] r2 = FirmaUtils.rsaPubDecrypt(sig, FirmaUtils.cargarLlavePublica(PUB));
            out.writeUTF(Arrays.equals(reto,r2)?"OK":"ERROR");
            if (!Arrays.equals(reto,r2)) throw new SecurityException("reto");

            /* 5 recibir (G,P,Gx, sig) */
            byte[] bloque=readBlock(in);
            byte[] sigGP = readBlock(in);
            if (!FirmaUtils.verificarFirma(bloque,sigGP,FirmaUtils.cargarLlavePublica(PUB)))
                throw new SecurityException("firma GP");

            DataInputStream din=new DataInputStream(new ByteArrayInputStream(bloque));
            byte[] G=readBlock(din), P=readBlock(din), Gx=readBlock(din);

            out.writeUTF("OK");   // paso 6

            /* 7 enviar Gy */
            DHParameterSpec spec=new DHParameterSpec(new java.math.BigInteger(P),
                                                     new java.math.BigInteger(G));
            KeyPairGenerator g=KeyPairGenerator.getInstance("DH");
            g.initialize(spec);  KeyPair kp=g.generateKeyPair();
            byte[] Gy=kp.getPublic().getEncoded();
            out.writeInt(Gy.length); out.write(Gy);

            /* 8 recibir tabla */
            KeyAgreement ka=KeyAgreement.getInstance("DH");
            PublicKey srvPub=KeyFactory.getInstance("DH")
                              .generatePublic(new X509EncodedKeySpec(Gx));
            ka.init(kp.getPrivate()); ka.doPhase(srvPub,true);
            SecretKey[] keys=derive(ka.generateSecret());
            SecretKey kAES=keys[0], kMAC=keys[1];

            byte[] iv  =readBlock(in);
            byte[] c   =readBlock(in);
            byte[] h   =readBlock(in);
            if(!HMACUtils.validarHMAC(c,h,kMAC)) throw new SecurityException("HMAC tabla");
            String tabla=new String(AESUtils.descifrar(c,kAES,iv));
            if(!silent){System.out.println("===SERVICIOS===\n"+tabla);}

            /* 9 enviar id+ipCliente */
            ByteArrayOutputStream bos=new ByteArrayOutputStream();
            DataOutputStream dos=new DataOutputStream(bos);
            dos.writeInt(id);
            dos.writeInt(((InetSocketAddress)s.getLocalSocketAddress()).getAddress()
                             .hashCode());   
            byte[] pet=bos.toByteArray();
            byte[] ivC=AESUtils.generarIV();
            byte[] cPet=AESUtils.cifrar(pet,kAES,ivC);
            byte[] hPet=HMACUtils.generarHMAC(cPet,kMAC);
            out.writeInt(ivC.length); out.write(ivC);
            out.writeInt(cPet.length);out.write(cPet);
            out.writeInt(hPet.length);out.write(hPet);

            /* 10 recibir respuesta */
            byte[] iv2 =readBlock(in);
            byte[] c2  =readBlock(in);
            byte[] h2  =readBlock(in);
            if(!HMACUtils.validarHMAC(c2,h2,kMAC)) throw new SecurityException("HMAC resp");
            byte[] resp=AESUtils.descifrar(c2,kAES,iv2);
            DataInputStream dr=new DataInputStream(new ByteArrayInputStream(resp));
            int ipS=dr.readInt(), portS=dr.readInt();
            if(!silent){
                if(ipS==-1) System.out.println("Id no válido");
                else{
                    byte[] ipB=ByteBuffer.allocate(4).putInt(ipS).array();
                    System.out.printf("Srv → %s:%d%n",
                        InetAddress.getByAddress(ipB).getHostAddress(),portS);
                }
            }
            out.writeUTF("OK");   // paso 11
        }
        return System.nanoTime()-t0;
    }

    /* Callable */
    @Override public Long call() throws Exception {
        long sum=0; for(int i=0;i<reps;i++) sum+=round(idServ); return sum;}

    /* main */
    public static void main(String[] args){
        try{
            if(args.length==0){
                System.out.print("id servicio: "); int id=new Scanner(System.in).nextInt();
                new Cliente().round(id);
            }else if(args.length==2){
                long ns=new Cliente(Integer.parseInt(args[0]),
                                    Integer.parseInt(args[1])).call();
                System.out.printf("prom %.3f ms%n",(ns/Integer.parseInt(args[1]))/1e6);
            }else System.err.println("uso: Cliente [id reps]");
        }catch(Exception e){e.printStackTrace();}
    }
}
