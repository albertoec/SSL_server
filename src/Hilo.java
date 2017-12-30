
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
import java.io.File;
import java.util.Date;

import javax.net.ssl.SSLSocket;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author expploitt
 */
public class Hilo implements Runnable {

    public static final int NO_OPERATION = 0;
    public static final int REGISTRAR = 1;
    public static final int RECUPERAR = 2;
    public static final int READY = 255;
    private final SSLSocket socket;
    private SignedReader signedReader;
    private SignedWriter signedWriter;

    public Hilo(SSLSocket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {

        System.out.println("Nuevo cliente con dirección IP ->" + socket.getInetAddress().toString());
 
        try {

            socket.getRemoteSocketAddress(); // intrucción para forzar el inicio del handshake
            socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

            signedReader = new SignedReader(socket);
            signedWriter = new SignedWriter(socket);

            int i = signedReader.read();
            System.out.println("Leyendo..." + i);
            if (i == REGISTRAR) {
                registrar_documento();

            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    private void registrar_documento() {
        try {
            signedWriter.write(READY);
            System.out.println("Escribiendo... " + READY);
            signedWriter.flush();

            Object[] datos = signedReader.ReadSignedFile(new File("temporal.txt"));

            if (!SSL_server.verifyCert((byte[]) datos[5])) { //Validacion de certificado de documento.
                signedWriter.writeString(SSL_server.FAIL_SIGN);
                return;
            }
            if (!SSL_server.verify((String) datos[3], (byte[]) datos[4])) { //Validacion de firma de documento.
                signedWriter.writeString(SSL_server.FAIL_CERT);
                return;
            } 
             else {
                System.out.print("\nescribe");
                signedWriter.writeString(SSL_server.OK);
            }
            signedWriter.flush();
            //NUMERO DE REGISTRO (idRegistro). FALTA IMPLEMENTAR.
            //Sello temporal
            Date selloTemporal = new Date();
            String sello = selloTemporal.toString();
            //Sello listo
            //firmar documento
          // SSL_server.sign(datos[3],sello entry_alias);
            
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
