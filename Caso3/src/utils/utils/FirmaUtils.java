package utils;

import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;

/** Firmas SHA-256 con RSA y cifrado/descifrado PKCS1. */
public final class FirmaUtils {

    private FirmaUtils(){}

    /* ---------- carga de llaves ---------- */
    public static KeyPair cargarLlavesServidor() throws Exception {
        byte[] priv = Files.readAllBytes(Paths.get("llaves/llave_privada_servidor.der"));
        byte[] pub  = Files.readAllBytes(Paths.get("llaves/llave_publica_servidor.der"));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return new KeyPair(
            kf.generatePublic (new X509EncodedKeySpec (pub )),
            kf.generatePrivate(new PKCS8EncodedKeySpec(priv)));
    }
    public static PublicKey cargarLlavePublica(String ruta) throws Exception {
        byte[] b = Files.readAllBytes(Paths.get(ruta));
        return KeyFactory.getInstance("RSA")
                         .generatePublic(new X509EncodedKeySpec(b));
    }

    /* ---------- firma / verificación ---------- */
    public static byte[] firmarDatos(byte[] d, PrivateKey k) throws Exception {
        Signature s=Signature.getInstance("SHA256withRSA");
        s.initSign(k); s.update(d); return s.sign();
    }
    public static boolean verificarFirma(byte[] d, byte[] sig, PublicKey k) throws Exception {
        Signature s=Signature.getInstance("SHA256withRSA");
        s.initVerify(k); s.update(d); return s.verify(sig);
    }

    /* ---------- cifrado/descifrado RSA “crudo” ---------- */
    private static Cipher get() throws Exception { return Cipher.getInstance("RSA/ECB/PKCS1Padding"); }
    public static byte[] rsaPrivEncrypt(byte[] d, PrivateKey k) throws Exception {
        Cipher c=get(); c.init(Cipher.ENCRYPT_MODE,k); return c.doFinal(d);
    }
    public static byte[] rsaPubDecrypt(byte[] e, PublicKey k) throws Exception {
        Cipher c=get(); c.init(Cipher.DECRYPT_MODE,k); return c.doFinal(e);
    }
}
