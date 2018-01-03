
import Utils.DB.DBHandler;
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

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
            if(i == RECUPERAR){
                recuperar_documento();
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
            firma_server = SSL_server.sign(ruta_temp,id_registro,sello,firma_cliente,SSL_server.ENTRY_FIRMA); 
            //Fin FIRMA
            //Hay que cifrar?
            if(confidencialidad){
            	System.out.println("***CIFRANDO***");
            	String archivo = SSL_server.encrypt(ruta_temp);
            	byte[] descifrado=SSL_server.decryptByte(archivo);
            	String str = new String(descifrado, StandardCharsets.UTF_8);
            	System.out.println(str);
            	
            }
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
    
    private void recuperar_documento() throws Exception{
        
        try {
            signedWriter.write(READY);    
            System.out.println("Escribiendo... " + READY);
            signedWriter.flush();
            
            Object[] recibido = signedReader.ReadRecoveryRequest();
            String id_registro = (String) recibido[0];
            System.out.println("El numero de registro del documento solicitado es " + id_registro); 
            
            byte[] certificado = (byte[]) recibido[1];
            
            if (!SSL_server.verifyCert(certificado)) { //Validacion de certificado de documento.
                signedWriter.writeString(SSL_server.FAIL_SIGN);
                signedWriter.flush();
                return;
            } else {
                System.out.print("\nescribe");
                signedWriter.writeString(SSL_server.OK);
            }
            signedWriter.flush();
            
            ByteArrayInputStream inStream = new ByteArrayInputStream(certificado);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            
            String idCliente = cert.getIssuerDN().toString();
            System.out.println("\n" +idCliente);
            
            
        } catch (IOException ex) {
            Logger.getLogger(Hilo.class.getName()).log(Level.SEVERE, null, ex);
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
