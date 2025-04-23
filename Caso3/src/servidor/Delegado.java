package servidor;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import utils.AESUtils;
import utils.DHUtils;
import utils.FirmaUtils;
import utils.HMACUtils;
import utils.ServiciosUtils;

import java.util.*;

public class Delegado implements Runnable {
    private Socket socket;
    private Map<Integer, String> servicios;
    private KeyPair keyPair;

    public Delegado(Socket socket, Map<Integer, String> servicios, KeyPair keyPair) {
        this.socket = socket;
        this.servicios = servicios;
        this.keyPair = keyPair;
    }

    public void run() {
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            // === Paso 1: Establecer llave maestra con Diffie-Hellman ===
            KeyAgreement acuerdoServidor = DHUtils.generarAcuerdoServidor(in, out);
            byte[] llaveMaestra = acuerdoServidor.generateSecret();
            byte[] digest = MessageDigest.getInstance("SHA-512").digest(llaveMaestra);
            SecretKey llaveAES = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
            SecretKey llaveHMAC = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HmacSHA256");

            // === Paso 2: Preparar y enviar la tabla de servicios ===
            StringBuilder tabla = new StringBuilder();
            for (Map.Entry<Integer, String> entry : servicios.entrySet()) {
                tabla.append(entry.getKey()).append(".").append(entry.getValue()).append("\n");
            }
            byte[] mensaje = tabla.toString().getBytes();
            byte[] iv = AESUtils.generarIV();
            byte[] cifrado = AESUtils.cifrar(mensaje, llaveAES, iv);
            byte[] hmac = HMACUtils.generarHMAC(cifrado, llaveHMAC);
            byte[] firma = FirmaUtils.firmarDatos(mensaje, keyPair.getPrivate());

            out.writeInt(iv.length);
            out.write(iv);
            out.writeInt(cifrado.length);
            out.write(cifrado);
            out.writeInt(hmac.length);
            out.write(hmac);
            out.writeInt(firma.length);
            out.write(firma);

            // === Paso 3: Recibir consulta ===
            int id = in.readInt();
            if (!servicios.containsKey(id)) {
                out.writeInt(-1);
                out.writeInt(-1);
            } else {
                String[] ipPuerto = ServiciosUtils.obtenerIPyPuerto(id);
                out.writeInt(Integer.parseInt(ipPuerto[0]));
                out.writeInt(Integer.parseInt(ipPuerto[1]));
            }

        } catch (Exception e) {
            System.out.println("[ERROR Delegado]: " + e.getMessage());
        }
    }
}
