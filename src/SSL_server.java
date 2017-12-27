
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;


/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author expploitt
 */
public class SSL_server {

    private static final String IP = "localhost";
    private static final int PORT = 8080;
    private static final String RAIZ = "/home/expploitt/";
    private static String keyStore, trustStore;
    private static String keyStorePass, trustStorePass;
    
    public static void main(String[] args) {

        if (args.length != 5) {
            System.out.println("Uso: SSL_server keyStoreFile contraseñaKeystore truststoreFile contraseñaTruststore algoritmoCifrado");
        }

        keyStore = args[0].trim();
        keyStorePass = args[1].trim();
        trustStore = args[2].trim();
        trustStorePass= args[3].trim();
        
        try {

            new SSL_server().definirKeyStores();

            SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSL_server.getServerSocketFactory("TLS");
            SSLServerSocket socket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT);

            System.out.println("*************************");
            System.out.println("* Servidor inicializado *");
            System.out.println("*************************");

            while (true) {

                Runnable thread = new Hilo((SSLSocket) socket.accept());
                new Thread(thread).start();
            }
        } catch (IOException ex) {
            Logger.getLogger(SSL_server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void definirKeyStores() {

        String raiz = "/home/expploitt/";

        System.setProperty("javax.net.debug", "all");
        // ----  Almacenes mios  -----------------------------
        // Almacen de claves
        System.setProperty("javax.net.ssl.keyStore", raiz + "serverKeystore.jce");
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", "123456789");

        // Almacen de confianza
        System.setProperty("javax.net.ssl.trustStore", raiz + "serverTruststore.jce");
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "123456789");

    }
    
    /**
     * ****************************************************
     * getServerSocketFactory(String type) {}
    ****************************************************
     */
    private static ServerSocketFactory getServerSocketFactory(String type) {

        if (type.equals("TLS")) {
            
            SSLServerSocketFactory ssf;

            try {

                // Establecer el keymanager para la autenticacion del servidor
                SSLContext ctx;
                KeyManagerFactory kmf;
                TrustManagerFactory tmf;
                KeyStore ks, ts;
                
                
                char[] contraseñaKeyStore = keyStorePass.toCharArray();
                char[] contraseñaTrustStore = trustStorePass.toCharArray();

                ctx = SSLContext.getInstance("TLS");
                kmf = KeyManagerFactory.getInstance("SunX509");
                tmf = TrustManagerFactory.getInstance("SunX509");

                ks = KeyStore.getInstance("JCEKS");
                ts = KeyStore.getInstance("JCEKS");
                
                ks.load(new FileInputStream(RAIZ + keyStore +  ".jce"), contraseñaKeyStore);
                ts.load(new FileInputStream(RAIZ + trustStore +  ".jce"), contraseñaTrustStore);
                
                kmf.init(ks, contraseñaKeyStore);
                tmf.init(ts);

                ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

                ssf = ctx.getServerSocketFactory();
                
                return ssf;
                
            } catch (Exception e) {

                e.printStackTrace();
            }

        } else {
            System.out.println("Usando la Factoria socket por defecto (no SSL)");

            return ServerSocketFactory.getDefault();
        }

        return null;
    }

}

class Hilo implements Runnable {

    private SSLSocket socket;

    public Hilo() {
        socket = null;
    }

    public Hilo(SSLSocket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {

        System.out.println("Nuevo cliente con dirección IP ->" + socket.getInetAddress().toString());
        try {
            socket.getInputStream().read(); // intrucción para forzar el inicio del handshake
            socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
        } catch (IOException ex) {
            Logger.getLogger(Hilo.class.getName()).log(Level.SEVERE, null, ex);
        }
       

    }

}
