package servidor;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import utils.FirmaUtils;

import java.util.*;

public class ServidorPrincipal {
    private static final int PUERTO = 5000;
    private static Map<Integer, String> servicios = new HashMap<>();

    static {
        servicios.put(1, "Consulta de estado de vuelo");
        servicios.put(2, "Disponibilidad de vuelos");
        servicios.put(3, "Costo de vuelo");
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = FirmaUtils.cargarLlavesServidor();
        ServerSocket servidor = new ServerSocket(PUERTO);
        System.out.println("Servidor Principal escuchando en puerto " + PUERTO);

        while (true) {
            Socket cliente = servidor.accept();
            new Thread(new Delegado(cliente, servicios, keyPair)).start();
        }
    }
}

