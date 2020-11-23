package redes;

import org.jnetpcap.packet.PcapPacket;

public class AnalizadorLLC {
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
    
    private static void printCodigoSAP ( int valor ) {
        System.out.printf("%02X - ", (byte)valor);
        switch ((valor)&0xFF) {
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
    
    private static void printCodigoU ( int valor ) {
        System.out.printf("Código de trama U: \n%02X - ",(byte)valor);
        switch ( valor & (0x1F) ) {
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
    
    private static int getIthBit( int data, int i ) {
        return (data >> i) & 1;
    }
    private static void printCodigoSupervision ( byte ss ) {
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
    
    public static void analizar_paquete (PcapPacket trama) {
        System.out.printf("\nTrama IEEE802.3: LLC\n");
        int longitud = (trama.getUByte(12)*256) + trama.getUByte(13);

        if(longitud < 1500){
            System.out.println("\n|--- Trama IEEE802.3 ---|\n");
            System.out.printf("\nLongitud: %d (%04X)\n\n",longitud,longitud );
            // IMPRIMIR MAC DESTINO
            System.out.printf("MAC DESTINO: ");
            for ( int i = 0 ; i < 6 ; i++ )
                System.out.printf("%02X ",trama.getByte(i));
            System.out.printf("\n");

            // IMPRIMIR MAC ORIGEN
            System.out.printf("MAC ORIGEN: ");
            for ( int i = 6 ; i < 12 ; i++ )
                System.out.printf("%02X ",trama.getByte(i));
            System.out.printf("\n\n");
            // IMPRIMIR TIPO DE SERVICIO SAP
            byte dsap = trama.getByte(14);
            System.out.printf("DSAP: ");
            printCodigoSAP(dsap);
            byte ssap = trama.getByte(15);
            System.out.printf("SSAP: ");
            printCodigoSAP(ssap);
            byte control = trama.getByte(16);
            // IMPRIMIR CARACTERISTICAS DE CONTROL
            if ( longitud > 3 )
            { // Modo extendido
                byte ctl_extendido = trama.getByte(17);
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
        System.out.println("\n\nTrama en Crudo: \n\n"+ trama.toHexdump());
    }
}
