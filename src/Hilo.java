
import Utils.DB.DBData;
import Utils.socket.SignedReader;
import Utils.socket.SignedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
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
            X509Certificate cert = SSL_server.getCertificateByAlias(SSL_server.ENTRY_FIRMA);
            if (cert == null) {
                signedWriter.writeString(SSL_server.FAIL_INTERNO);
                signedWriter.flush();
                return;
            }
            signedWriter.writeString(SSL_server.OK);
            signedWriter.sendRegisterResponse(id_registro, sello, firma_server, cert);
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

        try {
            signedWriter.write(READY);
            System.out.println("Escribiendo... " + READY);
            signedWriter.flush();

            Object[] recibido = signedReader.ReadRecoveryRequest();
            String id_registro = (String) recibido[0];
            System.out.println("El numero de registro del documento solicitado es " + id_registro);

            //Compruebo si tenemos el id_registro en nuestra base de datos, de no ser así no existe el documento
            if (SSL_server.HANDLER.getData((long) Integer.parseInt(id_registro)) == null) {
                signedWriter.writeString("DOCUMENTO NO EXISTENTE");
                signedWriter.flush();
                return;
            } else {
                signedWriter.writeString("EXISTE DOCUMENTO");
                signedWriter.flush();
            }

            //Tenemos un id_registro en nuestra base de datos que se corresponde al que nos solicitan
            DBData datos = SSL_server.HANDLER.getData((long) Integer.parseInt(id_registro));

            if (!datos.getConfidencialidad()) { //Si el documento es publico
                //Le enviamos al cliente la confidencialidad del documento
                signedWriter.writeString("PUBLICO");
                signedWriter.flush();

                String sello = datos.getSello();
                String ruta = datos.getRuta();
                byte[] firma_registrador = datos.getFirma_servidor();
                byte[] firma_cliente = datos.getFirma_cliente();
                X509Certificate cert_firma_servidor = SSL_server.getCertificate(SSL_server.getKeyStore(), SSL_server.getKeyStorePass(), SSL_server.ENTRY_FIRMA);

                //Enviamos la respuesta
                boolean respuesta = signedWriter.sendRecoveryResponse(id_registro, ruta, sello, firma_registrador, cert_firma_servidor, datos.getNombre());

                if (respuesta) {
                    System.out.println("Se ha enviado la respuesta correctamente");
                } else {
                    System.out.println("Error al enviar la respuesta");
                }
            } else { //El documento es privado

                signedWriter.writeString("PRIVADO");
                signedWriter.flush();

                byte[] certificado = (byte[]) recibido[1];

                if (!SSL_server.verifyCert(certificado)) { //Validacion del certificado del cliente
                    signedWriter.writeString(SSL_server.FAIL_SIGN);
                    signedWriter.flush();
                    return;
                } else {
                    signedWriter.writeString(SSL_server.OK);
                }
                signedWriter.flush();

                ByteArrayInputStream inStream = new ByteArrayInputStream(certificado);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

                String idCliente = cert.getIssuerDN().toString();

                System.out.println(idCliente);
                System.out.println(datos.getUsuario());

                String[] fragmentos = idCliente.split(",");

                idCliente = fragmentos[0].trim().replace("CN=", "");

                System.out.println(idCliente);

                if (!idCliente.equals(datos.getUsuario())) {
                    signedWriter.writeString("ACCESO NO PERMITIDO");
                    signedWriter.flush();
                    return;
                } else {
                    signedWriter.writeString("USUARIO CORRECTO");
                    signedWriter.flush();
                }

                String temporal = getRutaTemporal();

                SSL_server.Cifrador.decrypt(datos.getRuta(), temporal);

                String sello = datos.getSello();
                byte[] firma_registrador = datos.getFirma_servidor();
                byte[] firma_cliente = datos.getFirma_cliente();
                X509Certificate cert_firma_servidor = SSL_server.getCertificate(SSL_server.getKeyStore(), SSL_server.getKeyStorePass(), "servidor".concat("-firma-rsa"));

                //Enviamos la respuesta
                boolean flag = signedWriter.sendRecoveryResponse(id_registro, temporal, sello, firma_registrador, cert_firma_servidor, datos.getNombre());

                if (flag) {
                    System.out.println("Se ha enviado la respuesta correctamente");
                } else {
                    System.out.println("Error al enviar la respuesta");
                }

            }
        } catch (IOException ex) {
            Logger.getLogger(Hilo.class.getName()).log(Level.SEVERE, null, ex);
        }

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
