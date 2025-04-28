 package servidor;

 import java.io.*;
 import java.net.Socket;
 import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
 import java.util.*;
 
 import utils.*;
 
 public class Delegado implements Runnable {
 
     private final Socket sock;
     private final Map<Integer, String> servicios;
     private final KeyPair llaveSrv;
 
     public Delegado(Socket s, Map<Integer, String> map, KeyPair kp) {
         sock = s;
         servicios = map;
         llaveSrv = kp;
     }
 
     @Override public void run() {
         try { sock.setTcpNoDelay(true); atender(); }
         catch (Exception e) { System.out.println(
            //"[ERROR Delegado]: " + e
            ); 
        }
     }
 
     /* ----------------------------------------------------------- */
     private void atender() throws Exception {
 
         DataInputStream  in  = new DataInputStream(sock.getInputStream());
         DataOutputStream out = new DataOutputStream(sock.getOutputStream());
 
         /*  1-4  HELLO + RETO */
         if (!"HELLO".equals(in.readUTF())) return;
 
         byte[] reto = new byte[in.readInt()]; in.readFully(reto);
         byte[] sigReto = FirmaUtils.rsaPrivEncrypt(reto, llaveSrv.getPrivate());
         out.writeInt(sigReto.length); out.write(sigReto);
 
         if (!"OK".equals(in.readUTF())) return;
 
         /* 5-7  DH + firma */
         KeyPair parDH = KeyPairGenerator.getInstance("DH").generateKeyPair();
 
         /* (G,P,Gx) como bloque */
         ByteArrayOutputStream bb = new ByteArrayOutputStream();
         DataOutputStream db = new DataOutputStream(bb);
 
         byte[] G  = ((DHPublicKey) parDH.getPublic()).getParams().getG().toByteArray();
         byte[] P  = ((DHPublicKey) parDH.getPublic()).getParams().getP().toByteArray();
         byte[] Gx = parDH.getPublic().getEncoded();
 
         db.writeInt(G.length);  db.write(G);
         db.writeInt(P.length);  db.write(P);
         db.writeInt(Gx.length); db.write(Gx);
         byte[] bloqueGP = bb.toByteArray();
 
         long tSign0 = System.nanoTime();                     
         byte[] sigGP = FirmaUtils.firmarDatos(bloqueGP, llaveSrv.getPrivate());
         long tSign   = System.nanoTime() - tSign0;
 
         out.writeInt(bloqueGP.length); out.write(bloqueGP);
         out.writeInt(sigGP.length);    out.write(sigGP);
 
         if (!"OK".equals(in.readUTF())) return;
 
         /* Recibir G */
         byte[] Gy = new byte[in.readInt()]; in.readFully(Gy);
         PublicKey pubCli = KeyFactory.getInstance("DH")
                             .generatePublic(new X509EncodedKeySpec(Gy));
 
         /* Derivar llaves -> AES (0-31)  /  HMAC (32-63) */
         KeyAgreement ka = KeyAgreement.getInstance("DH");
         ka.init(parDH.getPrivate()); ka.doPhase(pubCli, true);
         byte[] secret = ka.generateSecret();
         byte[] dig = MessageDigest.getInstance("SHA-512").digest(secret);
 
         SecretKey kAES = new SecretKeySpec(Arrays.copyOfRange(dig, 0, 32),  "AES");
         SecretKey kMAC = new SecretKeySpec(Arrays.copyOfRange(dig, 32, 64), "HmacSHA256");
 
         /* 8  enviar tabla */
         StringBuilder sb = new StringBuilder();
         for (var e : servicios.entrySet())
             sb.append(e.getKey()).append('.').append(e.getValue()).append('\n');
         byte[] tabla = sb.toString().getBytes();
 
         long tCifTab0 = System.nanoTime();                   
         byte[] ivT = AESUtils.generarIV();
         byte[] cT  = AESUtils.cifrar(tabla, kAES, ivT);
         long tCifTabla = System.nanoTime() - tCifTab0;
 
         byte[] hT = HMACUtils.generarHMAC(cT, kMAC);
 
         out.writeInt(ivT.length); out.write(ivT);
         out.writeInt(cT.length);  out.write(cT);
         out.writeInt(hT.length);  out.write(hT);
 
         /* 9  recibir consulta  */
         byte[] ivQ = new byte[in.readInt()]; in.readFully(ivQ);
         byte[] cQ  = new byte[in.readInt()]; in.readFully(cQ);
         byte[] hQ  = new byte[in.readInt()]; in.readFully(hQ);
 
         long tVer0 = System.nanoTime();                     
         boolean okH = HMACUtils.validarHMAC(cQ, hQ, kMAC);
         long tVerif = System.nanoTime() - tVer0;
         if (!okH) return;
 
         byte[] plainQ = AESUtils.descifrar(cQ, kAES, ivQ);
         DataInputStream dQ = new DataInputStream(new ByteArrayInputStream(plainQ));
         int id = dQ.readInt(); int ipCli = dQ.readInt();  
 
         /* 10  responder  */
         ByteArrayOutputStream bos = new ByteArrayOutputStream();
         DataOutputStream dos = new DataOutputStream(bos);
         if (!servicios.containsKey(id)) { dos.writeInt(-1); dos.writeInt(-1); }
         else {
             String[] ipPort = ServiciosUtils.obtenerIPyPuerto(id);
             dos.writeInt(Integer.parseInt(ipPort[0]));
             dos.writeInt(Integer.parseInt(ipPort[1]));
         }
         byte[] resp = bos.toByteArray();
 
         /* (a) cifrado simétrico */
         long tSym0 = System.nanoTime();                  
         byte[] ivR = AESUtils.generarIV();
         byte[] cR  = AESUtils.cifrar(resp, kAES, ivR);
         long tCifRespSym = System.nanoTime() - tSym0;
 
         byte[] hR = HMACUtils.generarHMAC(cR, kMAC);
 
         /* (b) cifrado asimétrico (solo métrica) */
         long tAs0 = System.nanoTime();                     
         Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
         rsa.init(Cipher.ENCRYPT_MODE, llaveSrv.getPublic());
         rsa.doFinal(resp);
         long tCifRespAsim = System.nanoTime() - tAs0;
 
         /* enviar respuesta cifrada simétricamente */
         out.writeInt(ivR.length); out.write(ivR);
         out.writeInt(cR.length);  out.write(cR);
         out.writeInt(hR.length);  out.write(hR);
 
         /* paso 11: confirmación final */
         if ("OK".equals(in.readUTF())) sock.close();
 
         /* registrar métricas */
         utils.MetricsCollector.log(
                 tSign, tCifTabla, tVerif, tCifRespSym, tCifRespAsim);
     }
 }
 