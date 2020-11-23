package redes;

import java.io.*;
import java.util.*;
import org.jnetpcap.*;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

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
        lector.next();
        String ruta = lector.nextLine();
        pcap = Pcap.openOffline(ruta, buffer_de_errores);
        if (pcap == null) {
            System.err.printf("Error al acceder al dispositivo: "+ buffer_de_errores.toString());
            System.exit(1);
        }
    }
    
    private void elegir_interfaz_de_red () {
        int revision = Pcap.findAllDevs(dispositivos, buffer_de_errores);
        if (revision == Pcap.NOT_OK || dispositivos.isEmpty()) {
            System.err.printf("No se encontraron dispositivos %s", dispositivos.toString());
            System.exit(1);
        }
        
        System.out.println("Dispositivos encontrados:");
        int i = 0;
        for (PcapIf dispositivo : dispositivos) {
            String descripcion = (dispositivo.getDescription() != null) ? dispositivo.getDescription() : "Sin descripción";
            try {
                final byte[] mac = dispositivo.getHardwareAddress();
                String dir_mac = ( mac == null ) ? "No tiene direccion MAC" : byte_to_string(mac);
                System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, dispositivo.getName(), descripcion, dir_mac);
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
            System.exit(1);
        }
    }
    
    private void establecer_filtro () {
        PcapBpfProgram filter = new PcapBpfProgram();
        String expression =""; // "port 80";
        int optimize = 0; // 1 es true, 0 es false
        int netmask = 0;
        int r2 = pcap.compile(filter, expression, optimize, netmask);
        if (r2 != Pcap.OK) {
            System.out.println("Error al establecer filtro: " + pcap.getErr());
        }
        pcap.setFilter(filter);
    }
    
    private void capturar_al_vuelo () {
        elegir_interfaz_de_red();
        establecer_filtro();
    }
    
    private void iniciar_analisis () {
        PcapPacketHandler<String> manejador_de_paquetes = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket paquete, String usuario) {
                int longitud = (paquete.getUByte(12)*256) + paquete.getUByte(13);
                if ( longitud < 1500 ) {
                    AnalizadorLLC.analizar_paquete(paquete);
                } else {
                    System.out.println("\nTrama ETHERNET\n");
                    System.out.printf("\nLongitud: %d (%04X)\n\n",longitud,longitud );
                }
                System.out.println("\nTrama en Crudo: \n\n" + paquete.toHexdump());
            }
        };
        pcap.loop(-1, manejador_de_paquetes, " ");
        pcap.close();
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
        iniciar_analisis();
    }
}
