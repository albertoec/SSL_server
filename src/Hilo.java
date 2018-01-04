
import Utils.DB.DBData;
import Utils.DB.DBHandler;
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
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
    public static final int LISTAR = 3;
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

            switch (i) {
                case REGISTRAR:
                    System.out.println("***Registrar****");
                    registrar_documento();
                    break;
                case RECUPERAR:
                    System.out.println("***Recuperar****");
                    recuperar_documento();
                    break;
                case LISTAR:
                    System.out.println("****Listar****");
                    listar_documentos();
                    break;
                default:
                    break;
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
            if (!SSL_server.verifyCert(certificado)) { // Validacion de
                // certificado de
                // documento.
                signedWriter.writeString(SSL_server.FAIL_SIGN);
                signedWriter.flush();
                return;
            }
            if (!SSL_server.verify(ruta_temp, firma_cliente)) { // Validacion de
                // firma de
                // documento.
                signedWriter.writeString(SSL_server.FAIL_CERT);
                signedWriter.flush();
                return;
            }
            signedWriter.flush();
            // NUMERO DE REGISTRO (idRegistro). FALTA descomentar
            long id_registro = 0L;
            id_registro = SSL_server.HANDLER.getNextID();
            // Sello temporal
            Date selloTemporal = new Date();
            String sello = selloTemporal.toString();
            // Sello listo

            // firmar documento
            byte[] firma_server = null;
            firma_server = SSL_server.sign(ruta_temp, id_registro, sello, firma_cliente, SSL_server.ENTRY_FIRMA);
            // Fin FIRMA

            /**
             * una vez todo hecho solo queda mover el fichero a su localización
             * final y se guardan los datos en la DB
             */
            String ruta = SSL_server.moveFile(id_registro, usuario, ruta_temp, confidencialidad);
            if (ruta == null) {
                signedWriter.writeString(SSL_server.FAIL_INTERNO);
                signedWriter.flush();
                return;
            }
            System.out.println(id_registro);
            boolean resultado = SSL_server.HANDLER.newEntry(id_registro, ruta, nombre_doc, sello, firma_cliente, firma_server,
                    confidencialidad, usuario);
            if (!resultado) {
                signedWriter.writeString(SSL_server.FAIL_INTERNO);
                signedWriter.flush();
                return;
            }

            signedWriter.writeString(SSL_server.OK);
            signedWriter.flush();
            signedWriter.writeLong(id_registro);
            signedWriter.flush();

        } catch (Exception e) {
            try {
                signedWriter.writeString(SSL_server.FAIL_INTERNO);
                signedWriter.flush();
            } catch (IOException e1) {
                e1.printStackTrace();
            }

        }
    }

    private void recuperar_documento() throws Exception {

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
        System.out.println("\n" + idCliente);

    }

    public void listar_documentos() throws Exception {

        signedWriter.write(READY);
        System.out.println("Escribiendo... " + READY);
        signedWriter.flush();

        byte[] certificado = signedReader.ReadListDocumentRequest();

        /*validamos el certificado */
        if (!SSL_server.verifyCert(certificado)) {
            signedWriter.writeString(SSL_server.FAIL_CERT);
            signedWriter.flush();
            return;
        } else {
            System.out.println("\nescribe");
            signedWriter.writeString(SSL_server.OK);
        }
        
        /*Obtenemos el certificado X509*/
        ByteArrayInputStream inStream = new ByteArrayInputStream(certificado);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
             
        System.out.println(cert.getIssuerDN().getName());
        HashMap<String, ArrayList<DBData>> listas = SSL_server.HANDLER.getListado(cert.getIssuerDN().getName().split(",")[0].replace("CN=", ""));
        
        ArrayList<DBData> listaConfidenciales = listas.get("confidenciales");
        ArrayList<DBData> listaNoConfidenciales = listas.get("noconfidenciales");
        
        System.out.println(listaConfidenciales);
        System.out.println(listaNoConfidenciales);
        
        signedWriter.sendDocumentListRequest(listaConfidenciales);
        signedWriter.sendDocumentListRequest(listaNoConfidenciales);
        
        System.out.println("enviados los arraylist");
        
        /*si es correcto generamos la respuesta*/
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
