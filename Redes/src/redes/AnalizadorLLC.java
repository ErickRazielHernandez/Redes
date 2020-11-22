package redes;

import org.jnetpcap.packet.PcapPacket;
import static redes.Capturador.getIthBit;
import static redes.Capturador.printCodigoSAP;
import static redes.Capturador.printCodigoSupervision;
import static redes.Capturador.printCodigoU;

public class AnalizadorLLC {
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
