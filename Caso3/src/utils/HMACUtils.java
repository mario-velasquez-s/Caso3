package utils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class HMACUtils {
    public static byte[] generarHMAC(byte[] datos, SecretKey llave) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(llave);
        return mac.doFinal(datos);
    }
}

