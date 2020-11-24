package redes;

import org.jnetpcap.packet.PcapPacket;

public class AnalizadorARP {
    
    private static PcapPacket tramaARP;
    
    private static String imprimir_tipo_hardware ( ) {
        String mensaje = "";
        int tipo_hardware = (tramaARP.getByte(14)*256) + tramaARP.getByte(15);
        switch ( tipo_hardware ) {
            case 1:
                mensaje = "Ethernet (10Mb)";
            break;
            case 6:
                mensaje = "IEEE 802 Networks";
            break;    
            case 7:
                mensaje = "ARCNET";
            break;
            case 15:
                mensaje = "Frame Relay";
            break;
            case 16:
                mensaje = "Asynchronous Transfer Mode (ATM)";
            break;
            case 17:
                mensaje = " HDLC";
            break;
            case 18:
                mensaje = "Fibre Channel";
            break;
            case 19:
                mensaje = "Asynchronous Transfer Mode (ATM)";
            break;
            case 20:
                mensaje = "Serial Line";
            break;
            default:
                mensaje = "Desconocido";
            break;
        }
        return mensaje + "(" + Integer.toString(tipo_hardware) + ")";
    }
    
    private static void imprimir_macs () {
        System.out.printf("MAC DESTINO: \t\t\t\t");
        for ( int i = 0 ; i < 6 ; i++ )
            System.out.printf("%02X ",tramaARP.getByte(i));
        System.out.printf("\n");

        System.out.printf("MAC ORIGEN: \t\t\t\t");
        for ( int i = 6 ; i < 12 ; i++ )
            System.out.printf("%02X ",tramaARP.getByte(i));
        System.out.printf("\n");
    }
    
    private static String imprimir_tipo_protocolo () {
        String mensaje = "";
        int tipo_protocolo = tramaARP.getByte(16)*256 + tramaARP.getByte(17);
        switch ( tipo_protocolo ) {
            case 2048:
                mensaje = "IP";
            break;
            default:
                mensaje = "Otro";
            break;
        }
        return mensaje + "(" + Integer.toString(tipo_protocolo) + ")";
    }
    
    public static String imprimir_longitud_direccion_fisica () {
        int longitud_dir_fisica = tramaARP.getByte(18);
        return Integer.toString(longitud_dir_fisica);
    }
    
    public static String imprimir_longitud_direccion_protocolo () {
        int longitud_dir_protocolo = tramaARP.getByte(19);
        return Integer.toString(longitud_dir_protocolo);
    }
    
    private static String imprimir_codigo_operacion () {
        String mensaje = "";
        int operacion = tramaARP.getByte(20)*256 + tramaARP.getByte(21);
        switch ( operacion ) {
            case 1:
                mensaje = "ARP Request";
            break;
            case 2:
                mensaje = "ARP Reply";
            break;
            case 3:
                mensaje = "RARP Request";
            break;
            case 4:
                mensaje = "RARP Reply";
            break;
            case 5:
                mensaje = "DRARP Request";
            break;
            case 6:
                mensaje = "DRARP Reply";
            break;
            case 7:
                mensaje = "DRARP Error";
            break;
            case 8:
                mensaje = "InARP Request";
            break;
            case 9:
                mensaje = "InARP Reply";
            break;
            default:
                mensaje = "Otro";
            break;
        }
        return mensaje + "(" + Integer.toString(operacion) + ")";
    }
    
    private static void  imprimir_mac_emisor () {
        for ( int i = 0 ; i < 6 ; i++ )
            System.out.printf("%02X ",tramaARP.getByte(22 + i));
        System.out.printf("\n");
    }
    
    private static void imprimir_mac_receptor () {
        for ( int i = 0 ; i < 6 ; i++ )
            System.out.printf("%02X ",tramaARP.getByte(32 + i));
        System.out.printf("\n");
    }
    
    public static void imprimir_direccion_emisor () {
        for ( int i = 0 ; i < 4 ; i++ ) {
            System.out.print(tramaARP.getByte( 28 + i) & 255);
            if ( i != 3 ){
                System.out.print(".");
            }
        }
        System.out.println("");
    }
    
    public static void imprimir_direccion_receptor () {
        for ( int i = 0 ; i < 4 ; i++ ) {
            System.out.print(tramaARP.getByte( 38 + i) & 255);
            if ( i != 3 ){
                System.out.print(".");
            }
        }
        System.out.println("");
    }
    
    public static void analizar_trama( PcapPacket trama ) {
        tramaARP = trama;
        System.out.println("TRAMA ARP\n");
        
        imprimir_macs();
        
        System.out.print("Tipo de hardware:\t\t\t");
        System.out.println(imprimir_tipo_hardware());
        
        System.out.print("Tipo de protocolo:\t\t\t");
        System.out.println(imprimir_tipo_protocolo());
        
        System.out.print("Longitud de dir. física:\t\t");
        System.out.println(imprimir_longitud_direccion_fisica());
        
        System.out.print("Longitud de ri. protocolo:\t\t");
        System.out.println(imprimir_longitud_direccion_protocolo());
        
        System.out.print("Código de operación:\t\t\t");
        System.out.println(imprimir_codigo_operacion());
        
        System.out.print("Dirección Física del Emisor:\t\t");
        imprimir_mac_emisor();
        
        System.out.print("Dirección de Protocolo del Emisor:\t");
        imprimir_direccion_emisor();
        
        System.out.print("Dirección Física del Receptor: \t\t");
        imprimir_mac_receptor();
        
        System.out.print("Dirección de Protocolo del Receptor:\t");
        imprimir_direccion_receptor();
    }
}
