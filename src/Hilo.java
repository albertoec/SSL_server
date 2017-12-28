
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

    private final SSLSocket socket;

    public Hilo(SSLSocket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {

        System.out.println("Nuevo cliente con dirección IP ->" + socket.getInetAddress().toString());

        try {

            socket.getRemoteSocketAddress(); // intrucción para forzar el inicio del handshake
            socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

            SignedReader signedReader = new  SignedReader(socket);
            SignedWriter signedWriter = new SignedWriter(socket);
            
            int i = signedReader.read();
            System.out.println("Leyendo..." + i);
            i = whatOperation(i);
            
            signedWriter.write(i);
            System.out.println("Escribiendo... " + " " + i);
            signedWriter.flush();
            
            Object[] datos = signedReader.ReadSignedFile(new File("temporal.txt"));
            
            if(!SSL_server.verify((String) datos[3], (byte[]) datos[4], "kp_clientfirma_certificate")){
                signedWriter.writeString(SSL_server.FAIL_CERT);
            }else if(!SSL_server.verifyCert( (byte[]) datos[5], "kp_clientfirma_certificate")){
                signedWriter.writeString(SSL_server.FAIL_SIGN);
            }else{
                System.out.print("escribe");
                signedWriter.writeString(SSL_server.OK);
                signedWriter.flush();
            }
            
            /*IMPLEMTAR LOS SELLOS TEMPORALES*/
            
        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    private static int whatOperation(int operation) {

        switch (operation) {
            case SSL_server.REGISTRAR:
                return SSL_server.READY;
            case SSL_server.RECUPERAR:
                break;
            default:
                return SSL_server.NO_OPERATION;
        }
        
        return 0;
    }
}
