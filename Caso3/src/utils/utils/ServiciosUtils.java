package utils;

/*
public class ServiciosUtils {
    public static String[] obtenerIPyPuerto(int servicioID) {
        // Puedes asignar IPs/puertos fijos o aleatorios
        switch (servicioID) {
            case 1: return new String[]{"127001", "6001"};
            case 2: return new String[]{"127001", "6002"};
            case 3: return new String[]{"127001", "6003"};
            default: return new String[]{"0", "0"};
        }
    }
}
    */

public final class ServiciosUtils {

    private ServiciosUtils(){}   // utilitario, no instanciable

    private static final int IP_LOCALHOST_INT = 0x7F000001;  // 127.0.0.1

    public static String[] obtenerIPyPuerto(int idServicio) {

        int puerto = 6000 + idServicio;          // 6001, 6002, 6003…
        return new String[] {
                String.valueOf(IP_LOCALHOST_INT), // índice 0
                String.valueOf(puerto)            // índice 1
        };
    }
}

