
import Utils.DB.DBHandler;
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
import java.io.File;
import java.security.MessageDigest;
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
            String ruta_temp = getRutaTemporal();
            Object[] datos = signedReader.ReadSignedFile(new File(ruta_temp));
            String usuario = (String) datos[0];
            String nombre_doc = (String) datos[1];
            Boolean confidencialidad = (Boolean) datos[2];
            byte[] firma_cliente = (byte[]) datos[4];
            byte[] certificado = (byte[]) datos[5];
            if (!SSL_server.verifyCert(certificado)) { //Validacion de certificado de documento.
                signedWriter.writeString(SSL_server.FAIL_SIGN);
                signedWriter.flush();
                return;
            }
            if (!SSL_server.verify(ruta_temp, firma_cliente)) { //Validacion de firma de documento.
                signedWriter.writeString(SSL_server.FAIL_CERT);
                signedWriter.flush();
                return;
            } else {
                System.out.print("\nescribe");
                signedWriter.writeString(SSL_server.OK);
            }
            signedWriter.flush();
            //NUMERO DE REGISTRO (idRegistro). FALTA descomentar
            long id_registro = 0L;
            //id_registro = handler.getNextID();
            //Sello temporal
            Date selloTemporal = new Date();
            String sello = selloTemporal.toString();
            //Sello listo

            //firmar documento
            byte[] firma_server = null;
            // firma_server = SSL_server.sign(datos[3],sello entry_alias); //en construccion
            /**
             * una vez todo hecho solo queda mover el fichero a su localización
             * final y se guardan los datos en la DB
             */
            String ruta =SSL_server.moveFile(id_registro, usuario, ruta_temp, confidencialidad);
            //handler.newEntry(id_registro, ruta, nombre_doc, sello, firma_cliente, firma_server, confidencialidad, usuario);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Obtiene una ruta temporal no utilizada
     *
     * @return Ruta temporal
     */
    private String getRutaTemporal() {
        String temp = "temp";
        long i = 0L;
        while (new File(temp + i).exists()) {
            i++;
        }
        return temp + i;
    }
}
