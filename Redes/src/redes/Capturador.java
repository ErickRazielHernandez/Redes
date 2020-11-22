package redes;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;



public class Capturador {
    
    private static String asString(final byte[] mac) {
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
        public static int getIthBit( int data, int i ) {
            return (data >> i) & 1;
        }
        public static String stringByteToBinary ( byte number ) {
            String binary = "";
            for ( int i = 7 ; i >= 0 ; i-- ) {
                if ( getIthBit(number, i) == 1 ) 
                    binary.concat("1");
                else
                    binary.concat("0");
            }
            System.out.println("Valor en binario "+binary);
            return binary;
        }
        public static void printCodigoSupervision ( byte ss )
        {
            System.out.printf("Código de Supervisión: ");
            switch (ss) {
                case 0:
                    System.out.printf("(RR) Listo para recibir : %d%d",
                            getIthBit(ss, 1), getIthBit(ss, 0));
                break;
                case 1:
                    System.out.printf("(REJ) Rechazo : %d%d",
                            getIthBit(ss, 1), getIthBit(ss, 0));
                break;
                case 2:
                    System.out.printf("(RNR) Receptor No listo para recibir : %d%d",
                            getIthBit(ss, 1), getIthBit(ss, 0));
                break;
                case 3:
                    System.out.printf("(SREJ) Rechazo Selectivo : %d%d",
                            getIthBit(ss, 1), getIthBit(ss, 0));
                break;
            }
        }
        public static void printCodigoSAP ( int valor )
        {
            System.out.printf("%02X - ", (byte)valor);
            switch ((valor)&0xFF)
            {
                case 0x00:
                    System.out.println("Null SAP");
                    break;
                case 0x04:
                    System.out.println("SNA");
                    break;
                case 0x05:
                    System.out.println("SNA");
                    break;
                case 0x06:
                    System.out.println("TCP");
                    break;
                case 0x08:
                    System.out.println("SNA");
                    break;
                case 0x0C:
                    System.out.println("SNA");
                    break;
                case 0x42:
                    System.out.println("Spanning Tree");
                    break;
                case 0x7F:
                    System.out.println("ISO 802.2");
                    break;
                case 0x80:
                    System.out.println("XNS");
                    break;
                case 0xAA:
                    System.out.println("SNAP");
                    break;
                case 224:
                    System.out.println("IPX");
                    break;
                case 240:
                    System.out.println("NetBIOS");
                    break;
                case 0xF8:
                    System.out.println("RPL");
                    break;
                case 0xFC:
                    System.out.println("RPL");
                    break;
                case 0xFE:
                    System.out.println("OSI");
                    break;
                case 0xFF:
                    System.out.println("Global SAP");
                    break;
                default:
                    System.out.println("Otro");
                    break;
            }
        }
        public static void printCodigoU ( int valor )
        {
            System.out.printf("Código de trama U: \n%02X - ",(byte)valor);
            switch ( valor & (0x1F) )
            {
                case 0x10:
                    System.out.println("SNRM : Activación modo respuesta normal");
                    break;
                case 0x1B:
                    System.out.println("SNRME : Activación modo respuesta normal (ampliado)");
                    break;
                case 0x07:
                    System.out.println("SABM : Activación modo respuesta asíncrona balanceada");
                    break;
                case 0x0F:
                    System.out.println("SABME : Activación modo respuesta asíncrona balanceada (ampliado)");
                    break;
                case 0x00:
                    System.out.println("Información sin numerar");
                    break;
                case 0x0C:
                    System.out.println("Reconocimiento sin numerar");
                    break;
                case 0x08:
                    System.out.println("DISC : Desconexión o petición de desconexión");
                    break;
                case 0x01:
                    System.out.println("SIM : Activación de modo petición de información ");
                    break;
                case 0x04:
                    System.out.println("UP : Muestra sin numerar");
                    break;
                case 0x13:
                    System.out.println("RSET : Reset");
                    break;
                case 0x17:
                    System.out.println("XID : Intercambio de ID");
                    break;
                case 0x11:
                    System.out.println("FRMR : Rechazo de trama");
                    break;
                default:
                    System.out.println("Otro");
                    break;
            }
        }
    
    public static void main(String[] args) {
            Pcap pcap=null;
            try{
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));   
            List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
            StringBuilder errbuf = new StringBuilder(); // For any error msgs
            System.out.println("[0]-->Realizar captura de paquetes al vuelo");
            System.out.println("[1]-->Cargar traza de captura desde archivo");
            System.out.print("\nElige una de las opciones:");
            int opcion = Integer.parseInt(br.readLine());
            if (opcion==1){
                /////////////////////////lee archivo//////////////////////////
                String fname = "paquetes3.pcap";
                pcap = Pcap.openOffline(fname, errbuf);
                if (pcap == null) {
                  System.err.printf("Error while opening device for capture: "+ errbuf.toString());
                  return;
                 }//if
            } else if(opcion==0){
            /***************************************************************************
             * Obtener lista de dispositivos disponibles
             **************************************************************************/
            int r = Pcap.findAllDevs(alldevs, errbuf);
            if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                    System.err.printf("Can't read list of devices, error is %s", errbuf
                        .toString());
                    return;
            }

            System.out.println("Dispositivos encontrados:");

            int i = 0;
            for (PcapIf device : alldevs) {
                    String description =
                        (device.getDescription() != null) ? device.getDescription()
                            : "Sin descripción";
                    final byte[] mac = device.getHardwareAddress();
                    String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                    System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                    List<PcapAddr> direcciones = device.getAddresses();
                    for(PcapAddr direccion:direcciones){
                        System.out.println(direccion.getAddr().toString());
                    }//foreach

            }//for

            System.out.print("\nEscribe el número de interfaz a utilizar:");
            int interfaz = Integer.parseInt(br.readLine());
            PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device
            System.out
                .printf("\nChoosing '%s' on your behalf:\n",
                    (device.getDescription() != null) ? device.getDescription()
                        : device.getName());

            /***************************************************************************
             * Second we open up the selected device
             **************************************************************************/
            /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
            64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */

            int snaplen = 64 * 1024;           // Capture all packets, no trucation
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
            int timeout = 10 * 1000;           // 10 seconds in millis


            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

            if (pcap == null) {
                    System.err.printf("Error while opening device for capture: "
                        + errbuf.toString());
                    return;
            }//if

            
            }

            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
                public void nextPacket(PcapPacket packet, String user) {
                    System.out.printf("\n|------------ TRAMA ------------|\n");
                    /*
                    System.out.printf("Paquete recibido el %s caplen=%-4d longitud=%-4d %s \n\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(),  // Length actually captured
                        packet.getCaptureHeader().wirelen(), // Original length
                        user                                 // User supplied object
                        );
                    */
                    int longitud = (packet.getUByte(12)*256)+packet.getUByte(13);

                    if(longitud < 1500){
                        System.out.println("\n|--- Trama IEEE802.3 ---|\n");
                        System.out.printf("\nLongitud: %d (%04X)\n\n",longitud,longitud );
                        // IMPRIMIR MAC DESTINO
                        System.out.printf("MAC DESTINO: ");
                        for ( int i = 0 ; i < 6 ; i++ )
                            System.out.printf("%02X ",packet.getByte(i));
                        System.out.printf("\n");

                        // IMPRIMIR MAC ORIGEN
                        System.out.printf("MAC ORIGEN: ");
                        for ( int i = 6 ; i < 12 ; i++ )
                            System.out.printf("%02X ",packet.getByte(i));
                        System.out.printf("\n\n");
                        // IMPRIMIR TIPO DE SERVICIO SAP
                        byte dsap = packet.getByte(14);
                        System.out.printf("DSAP: ");
                        printCodigoSAP(dsap);
                        byte ssap = packet.getByte(15);
                        System.out.printf("SSAP: ");
                        printCodigoSAP(ssap);
                        byte control = packet.getByte(16);
                        // IMPRIMIR CARACTERISTICAS DE CONTROL
                        if ( longitud > 3 )
                        { // Modo extendido
                            byte ctl_extendido = packet.getByte(17);
                            System.out.println("-- MODO EXTENDIDO --\n");
                            if ( getIthBit(control, 0) == 0 ){
                                System.out.println("--TRAMA TIPO I--");
                                byte pull_final = (byte)getIthBit(ctl_extendido, 0);
                                byte envio = (byte)((control >> 1)&(0x7F));
                                byte recibo = (byte)((ctl_extendido >> 1)&(0x7F));
                                System.out.printf("Pull/final: %s\n",(pull_final == 1)?"comando":"respuesta");
                                System.out.printf("Número de secuencia de envío: %d\n",envio);
                                System.out.printf("Número de secuencia de recibo: %d\n", recibo);
                            }
                            else if ( getIthBit(control, 1) == 0 ) 
                            {
                                System.out.println("--TRAMA TIPO S--");
                                byte pull_final = (byte)getIthBit(ctl_extendido, 0);
                                byte recibo = (byte)((ctl_extendido >> 1)&(0x7F));
                                byte ss = (byte)((control >> 2) & (3));
                                System.out.printf("Pull/final: %s\n",(pull_final == 1)?"comando":"respuesta");
                                System.out.printf("Número de secuencia de recibo: %d\n",recibo);
                                printCodigoSupervision(ss);
                            } 
                            else 
                            {
                                System.out.println("--TRAMA U--");
                                byte pull_final = (byte)((control >> 4)&(1));
                                byte parte1 = (byte)((control >> 5)&(7));
                                    byte parte2 = (byte)((control >> 2)&(3));
                                    byte valor = (byte)((parte1 << 2) + (parte2));
                                    printCodigoU(valor);
                                System.out.printf("Pull/final: %s\n",(pull_final == 1)?"comando":"respuesta");
                            }
                        }
                        else // Longitud <= 3
                        {
                            System.out.println("-- MODO NORMAL--\n");
                            if ( (control & 1) == 0 )
                            { // TRAMA DE INFORMACION
                                System.out.println("--TRAMA TIPO I--");
                                byte recibo = (byte)((control >> 5) & 7);
                                byte envio = (byte)((control >> 1) & 7);
                                byte pull_final = (byte)((control >> 4)&(1));
                                System.out.printf("Número de secuencia de recibo: %d\n",recibo);
                                System.out.printf("Número de secuencia de envio: %d\n",envio);
                                System.out.printf("Pull/final: %s\n",(pull_final == 1)?"comando":"respuesta");
                            }
                            else
                            {
                                if ( (control & 2) == 0 )
                                { // TRAMA SUPERVISION
                                    System.out.println("--TRAMA TIPO S--");
                                    byte recibo = (byte)((control >> 5) & 7);
                                    byte pull_final = (byte)((control >> 4)&(1));
                                    byte cod_supervision = (byte)((control >> 2)& (3));
                                    System.out.printf("Número de secuencia de recibo: %d\n",recibo);
                                    System.out.printf("Pull/final: %s\n",(pull_final == 1)?"comando":"respuesta");
                                    printCodigoSupervision(cod_supervision);
                                }
                                else
                                { // TRAMA SIN NUMERAR
                                    System.out.println("--TRAMA TIPO U--");
                                    byte pull_final = (byte)((control >> 4)&(1));
                                    byte parte1 = (byte)((control >> 5)&(7));
                                    byte parte2 = (byte)((control >> 2)&(3));
                                    byte valor = (byte)((parte1 << 2) + (parte2));
                                    printCodigoU(valor);
                                    System.out.printf("Pull/final: %s\n",(pull_final == 1)?"comando":"respuesta");
                                }
                            }
                        }
                    } else if(longitud>=1500){
                        System.out.println("\n-->Trama ETHERNET\n");
                        System.out.printf("\nLongitud: %d (%04X)\n\n",longitud,longitud );
                    }
                    // IMPRIME TRAMA EN CRUDO CON EQUIVALENCIA EN ASCII
                    System.out.println("\n\nTrama en Crudo: \n\n"+ packet.toHexdump());
                }
            };
            pcap.loop(-1, jpacketHandler, " ");
            pcap.close();
        }catch(IOException e){
            e.printStackTrace();
        }
    }
}
