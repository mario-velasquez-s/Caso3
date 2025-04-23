package utils;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.SecureRandom;

public class AESUtils {
    public static byte[] generarIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

     // Cifrar datos usando AES/CBC/PKCS5Padding
     public static byte[] cifrar(byte[] datos, SecretKey llave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, llave, ivSpec);
        return cipher.doFinal(datos);
    }

    // Descifrar datos usando AES/CBC/PKCS5Padding
    public static byte[] descifrar(byte[] datosCifrados, SecretKey llave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, llave, ivSpec);
        return cipher.doFinal(datosCifrados);
    }

}
