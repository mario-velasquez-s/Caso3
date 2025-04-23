


import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GeneradorLlavesRSA {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(1024);
        KeyPair parLlaves = generador.generateKeyPair();

        PublicKey llavePublica = parLlaves.getPublic();
        PrivateKey llavePrivada = parLlaves.getPrivate();

        //Guardar la llave pública
        try (FileOutputStream outPub = new FileOutputStream("llaves/llave_publica_servidor.der")) {
            outPub.write(llavePublica.getEncoded());
        }

        //Guardar la llave privada
        try (FileOutputStream outPriv = new FileOutputStream("llaves/llave_privada_servidor.der")) {
            outPriv.write(llavePrivada.getEncoded());
        }

        System.out.println("Llaves RSA generadas exitosamente.");
    }
}
