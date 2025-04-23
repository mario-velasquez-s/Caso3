package utils;

import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class FirmaUtils {
    public static byte[] firmarDatos(byte[] datos, PrivateKey clavePrivada) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(clavePrivada);
        firma.update(datos);
        return firma.sign();
    }

    public static KeyPair cargarLlavesServidor() throws Exception {
        byte[] privBytes = Files.readAllBytes(Paths.get("llaves/llave_privada_servidor.der"));
        byte[] pubBytes = Files.readAllBytes(Paths.get("llaves/llave_publica_servidor.der"));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);
        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));
        PrivateKey privKey = keyFactory.generatePrivate(privSpec);

        return new KeyPair(pubKey, privKey);
    }
}
