package utils;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class DHUtils {
    public static KeyAgreement generarAcuerdoServidor(DataInputStream in, DataOutputStream out) throws Exception {
        // Recibir parámetros DH del cliente
        int len = in.readInt();
        byte[] yBytes = new byte[len];
        in.readFully(yBytes);
        BigInteger y = new BigInteger(yBytes);

        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(keyPair.getPrivate());

        // Enviar clave pública al cliente
        byte[] publicKeyEnc = keyPair.getPublic().getEncoded();
        out.writeInt(publicKeyEnc.length);
        out.write(publicKeyEnc);

        // Construir clave pública del cliente
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        DHPublicKeySpec ySpec = new DHPublicKeySpec(y, dhSpec.getP(), dhSpec.getG());
        PublicKey pubKeyCliente = keyFactory.generatePublic(ySpec);
        ka.doPhase(pubKeyCliente, true);
        return ka;
    }
}
