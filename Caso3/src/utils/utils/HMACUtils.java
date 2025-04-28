package utils;

import java.security.MessageDigest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class HMACUtils {
    public static byte[] generarHMAC(byte[] datos, SecretKey llave) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(llave);
        return mac.doFinal(datos);
    }

public static boolean validarHMAC(byte[] datos,
                                      byte[] hmacRecibido,
                                      SecretKey llave) throws Exception {

        byte[] hmacCalculado = generarHMAC(datos, llave);
        /* MessageDigest.isEqual() compara en tiempo constante */
        return MessageDigest.isEqual(hmacCalculado, hmacRecibido);
    }
}

