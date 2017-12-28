
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
import java.io.File;
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

            if (!SSL_server.verify((String) datos[3], (byte[]) datos[4], "kp_clientfirma_certificate")) { //Archivo a guardar, firma y 
                signedWriter.writeString(SSL_server.FAIL_CERT);
            } else if (!SSL_server.verifyCert((byte[]) datos[5], "kp_clientfirma_certificate")) {
                signedWriter.writeString(SSL_server.FAIL_SIGN);
            } else {
                System.out.print("escribe");
                signedWriter.writeString(SSL_server.OK);
            }
            signedWriter.flush();
            /*IMPLEMTAR LOS SELLOS TEMPORALES*/

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
