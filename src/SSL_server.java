
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
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
    private static final String RAIZ = "";
    private static String keyStore, trustStore;
    private static String keyStorePass, trustStorePass;

    public static final int NO_OPERATION = 0;
    public static final int REGISTRAR = 1;
    public static final int RECUPERAR = 2;
    public static final int READY = 255;
    
    public static final String FAIL_CERT = "CERTIFICADO INCORRECTO";
    public static final String FAIL_SIGN = "FIRMA INCORRECTA";
    public static final String OK = "OK";

    public static void main(String[] args) {

        if (args.length != 5) {
            System.out.println("Uso: SSL_server keyStoreFile contraseñaKeystore truststoreFile contraseñaTruststore algoritmoCifrado");
        }

        keyStore = args[0].trim();
        keyStorePass = args[1].trim();
        trustStore = args[2].trim();
        trustStorePass = args[3].trim();

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

        //System.setProperty("javax.net.debug", "all");
        // ----  Almacenes mios  -----------------------------
        // Almacen de claves
        System.setProperty("javax.net.ssl.keyStore", "serverKeystore.jce");
        System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.keyStorePassword", "123456789");

        // Almacen de confianza
        System.setProperty("javax.net.ssl.trustStore", "serverTruststore.jce");
        System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "123456789");

    }

    /**
     * ****************************************************
     * getServerSocketFactory(String type) {}
     * ***************************************************
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

                ks.load(new FileInputStream(RAIZ + keyStore + ".jce"), contraseñaKeyStore);
                ts.load(new FileInputStream(RAIZ + trustStore + ".jce"), contraseñaTrustStore);

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

    public static byte[] sign(String docPath, String keyStore, String entry_alias) throws KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, UnrecoverableEntryException, InvalidKeyException, SignatureException, CertificateException {

        FileInputStream fmensaje = new FileInputStream(docPath);

        String provider = "SunJCE";
        String algoritmo = "SHA1withRSA";
        byte bloque[] = new byte[1024];
        long filesize = 0;
        int longbloque;

        // Variables para el KeyStore
        KeyStore ks;
        char[] ks_password = keyStorePass.toCharArray();
        char[] key_password = keyStorePass.toCharArray();

        System.out.println("******************************************* ");
        System.out.println("*               FIRMA                     * ");
        System.out.println("******************************************* ");

        // Obtener la clave privada del keystore
        ks = KeyStore.getInstance("JCEKS");

        ks.load(new FileInputStream(keyStore + ".jce"), ks_password);

        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(entry_alias, new KeyStore.PasswordProtection(key_password));
        System.err.println(pkEntry);
        PrivateKey privateKey = pkEntry.getPrivateKey();

        // Visualizar clave privada
        System.out.println("*** CLAVE PRIVADA ***");
        System.out.println("Algoritmo de Firma (sin el Hash): " + privateKey.getAlgorithm());
        System.out.println(privateKey);

        // Creamos un objeto para firmar/verificar
        Signature signer = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para firmar
        signer.initSign(privateKey);

        // Para firmar primero pasamos el hash al mensaje (metodo "update")
        // y despues firmamos el hash (metodo sign).
        byte[] firma;

        while ((longbloque = fmensaje.read(bloque)) > 0) {
            filesize = filesize + longbloque;
            signer.update(bloque, 0, longbloque);
        }

        firma = signer.sign();

        double v = firma.length;

        System.out.println("*** FIRMA: ****");
        for (int i = 0; i < firma.length; i++) {
            System.out.print(firma[i] + " ");
        }
        System.out.println();
        System.out.println();

        fmensaje.close();

        return firma;

    }

    public static boolean verify(String docPath, byte[] firma, String entry_alias) throws FileNotFoundException, CertificateException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, KeyStoreException {

        /**
         * *****************************************************************
         * Verificacion
         * ****************************************************************
         */
        System.out.println("************************************* ");
        System.out.println("        VERIFICACION                  ");
        System.out.println("************************************* ");

        
        byte bloque[] = new byte[1024];
        long filesize = 0;
        int longbloque;

        KeyStore ks;
        char[] ks_password = trustStorePass.toCharArray();

        ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(trustStore + ".jce"), ks_password);
        
        Enumeration<String> aliases = ks.aliases();
        
        while(aliases.hasMoreElements()){
            
        FileInputStream fmensajeV = new FileInputStream(docPath);
            
        String alias = aliases.nextElement();

        // Obtener la clave publica del keystore
        PublicKey publicKey = ks.getCertificate(alias).getPublicKey();

        System.out.println("*** CLAVE PUBLICA ***");
        System.out.println(publicKey);

        // Obtener el usuario del Certificado tomado del KeyStore.
        //   Hay que traducir el formato de certificado del formato del keyStore
        //	 al formato X.509. Para eso se usa un CertificateFactory.
        byte[] certificadoRaw = ks.getCertificate(alias).getEncoded();
        ByteArrayInputStream inStream;
        inStream = new ByteArrayInputStream(certificadoRaw);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

        // Creamos un objeto para verificar, pasandole el algoritmo leido del certificado.
        Signature verifier = Signature.getInstance(cert.getSigAlgName());
        System.out.println(cert.getSigAlgName());
        // Inicializamos el objeto para verificar
        verifier.initVerify(publicKey);

        while ((longbloque = fmensajeV.read(bloque)) > 0) {
            filesize = filesize + longbloque;
            verifier.update(bloque, 0, longbloque);
        }

        boolean resultado;

        resultado = verifier.verify(firma);

        System.out.println();
        if (resultado == true) {
            System.out.print("Verificacion correcta de la Firma");
            
            return true;

        }
        
            fmensajeV.close();

        }
            System.out.print("Fallo de verificacion de firma");
            return false;
    }

    public static boolean verifyCert(byte[] certificado, String entry_alias) throws Exception {

        KeyStore ks;
        ByteArrayInputStream inStream;
        PublicKey publicKey;
        char[] ks_password;
        
        ks_password = trustStorePass.toCharArray();
        ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(trustStore + ".jce"), ks_password);
        
         //Obtener el certificado de un array de bytes

        inStream = new ByteArrayInputStream(certificado);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        
        
        //Listamos los alias y después los recorremos en busca de un certificado que valga
        
        Enumeration<String> aliases = ks.aliases();
 
            while(aliases.hasMoreElements()){
                
                // Obtener la clave publica del keystore
                
                publicKey = ks.getCertificate(aliases.nextElement()).getPublicKey();

                try {

                    cert.verify(publicKey);                    
                    
                    System.out.println("\nCertificado correcto");

                    return true;
                    
                } catch (InvalidKeyException e) {

                } catch (SignatureException ex) {
                
                }
            } 
             
                               
            System.out.println("Certificado incorrecto");
            return false;
    }
}
