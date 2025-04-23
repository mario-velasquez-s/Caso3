package utils;

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

