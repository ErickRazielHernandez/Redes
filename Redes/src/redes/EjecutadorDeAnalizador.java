package redes;

import java.io.*;
import java.util.*;
import org.jnetpcap.*;

public class EjecutadorDeAnalizador {
    private Scanner lector;
    private List<PcapIf> dispositivos;
    private StringBuilder buffer_de_errores;
    private Pcap pcap;
    
    public EjecutadorDeAnalizador() {
        lector = new Scanner(System.in);
        dispositivos = new ArrayList<PcapIf>();
        buffer_de_errores = new StringBuilder();
        pcap = null;
    }
    
    private String byte_to_string (final byte[] mac) {
            final StringBuilder buf = new StringBuilder();
            for (byte b : mac) {
                if (buf.length() != 0) {
                    buf.append(':');
                }
                if (b >= 0 && b < 16) {
                    buf.append('0');
                }
                buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
            }
            return buf.toString();
        }
    
    private void leer_de_archivo ( ) {
        System.out.println("Ingrese la ruta del archivo");
        String ruta = lector.nextLine();
        pcap = Pcap.openOffline(ruta, buffer_de_errores);
        if (pcap == null) {
            System.err.printf("Error al acceder al dispositivo: "+ buffer_de_errores.toString());
            return;
        }
    }
    
    private void elegir_interfaz_de_red () {
        int revision = Pcap.findAllDevs(dispositivos, buffer_de_errores);
        if (revision == Pcap.NOT_OK || dispositivos.isEmpty()) {
            System.err.printf("No se encontraron dispositivos %s", dispositivos.toString());
            return;
        }
        
        System.out.println("Dispositivos encontrados:");
        int i = 0;
        for (PcapIf dispositivo : dispositivos) {
            String descripcion = (dispositivo.getDescription() != null) ? dispositivo.getDescription() : "Sin descripción";
            try {
                final byte[] mac = dispositivo.getHardwareAddress();
                String dir_mac = ( mac == null ) ? "No tiene direccion MAC" : byte_to_string(mac);
                System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, dispositivo.getName(), descripcion, dir_mac);
                List<PcapAddr> direcciones = dispositivo.getAddresses();
                for(PcapAddr direccion:direcciones){
                    System.out.println(direccion.getAddr().toString());
                }
            } catch ( Exception e ) {
                System.out.println(e.getMessage());
                e.printStackTrace();
            }
        }
        
        System.out.print("\nEscribe el número de interfaz a utilizar:");
        int interfaz = lector.nextInt();
        PcapIf device = dispositivos.get(interfaz); 
        System.out.printf("\nAbriendo interfaz: '%s' :\n",
            (device.getDescription() != null) ? device.getDescription(): device.getName());
        int longitud_captura = 64 * 1024;           
        int banderas = Pcap.MODE_PROMISCUOUS; // capturar todos los paquetes
        int tiempo_espera = 10 * 1000;           // Esperar 10 milis
        pcap = Pcap.openLive(device.getName(), longitud_captura, banderas, tiempo_espera, buffer_de_errores);
        if (pcap == null) {
            System.err.printf("Error al abrir la interfaz: " + buffer_de_errores.toString());
            return;
        }
    }
    
    private void establecer_filtro () {
        PcapBpfProgram filter = new PcapBpfProgram();
        String expression =""; // "port 80";
        int optimize = 0; // 1 means true, 0 means false
        int netmask = 0;
        int r2 = pcap.compile(filter, expression, optimize, netmask);
        if (r2 != Pcap.OK) {
            System.out.println("Filter error: " + pcap.getErr());
        }//if
        pcap.setFilter(filter);
    }
    
    private void capturar_al_vuelo () {
        elegir_interfaz_de_red();
        establecer_filtro();
        
    }
    
    public void mostrar_menu() {
        System.out.println("0) Realizar captura de paquetes al vuelo");
        System.out.println("1) Cargar paquetes desde archivo");
        System.out.print("\nElija una de las opciones:");
        int opcion = lector.nextInt();
        if (opcion == 1) {
            leer_de_archivo();
        } else {
            capturar_al_vuelo();
        }
        
    }
}
