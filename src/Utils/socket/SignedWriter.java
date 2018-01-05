/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils.socket;

import Utils.DB.DBData;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

/**
 *
 * @author eryalus
 */
public class SignedWriter extends SocketWriter {

    /**
     * Se le pasa el socket creado por la conexión y genera y maneja el
     * outputstream. Solo se puede crear una instancia de esta clase por socket
     * ya que abre el outputstream.
     *
     * @param soc Socket
     * @throws IOException
     */
    public SignedWriter(Socket soc) throws IOException {
        super(soc);
    }

    /**
     * Envía el documento, su firma, el id del cliente, el nombre del fichero,
     * el tipo de confidencialidad y la clave pública por este orden.
     *
     * @param id Identificador del usuario example@midominio.com
     * @param nombre_doc Nombre del documento
     * @param confidencialidad True si es privado o false si es público
     * @param ruta Ruta del fichero a enviar.
     * @param firma Firma del fichero a enviar.
     * @param certificado Certificado cn el que se ha firmado el documento
     * @return true si se ha enviado correctamente o false en caso contrario.
     */
    public boolean SendSignedFile(String id, String nombre_doc, boolean confidencialidad, String ruta, byte[] firma, X509Certificate certificado) {
        try {
            File file = new File(ruta);
            InputStream in = new FileInputStream(file);
            long longitud = file.length();
            writeLong(longitud); //manda la longitud del fichero para saver cuanto tiene que leer
            flush();
            byte[] bytes = new byte[1024];
            int leidos;
            while ((leidos = in.read(bytes)) > 0) {
                write(Arrays.copyOfRange(bytes, 0, leidos));
            }
            flush();
            in.close(); //ya se ha enviado el fichero, así que se cierra el doc
            writeLong(firma.length); //se envía la firma del doc. Primero su longitud
            write(firma);
            writeString(id); //se manda el identificador del cliente
            writeString(nombre_doc); //se manda el nombre del documento
            if (confidencialidad) { //se envia el tipo de confidencialidad
                write(1);
            } else {
                write(0);
            }
            byte[] clave = certificado.getEncoded(); //por último se envía el cert.
            writeLong(clave.length);
            write(clave);
            flush();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public boolean sendRecoveryRequest(String id_registro, X509Certificate certificado) {

        try {

            //Primero enviamos el identificador del documento que queremos recuperar
            writeString(id_registro);
            flush();

            //Después enviamos el certificado del cliente
            byte[] cert = certificado.getEncoded();
            writeLong(cert.length);
            write(cert);
            flush();

            return true;

        } catch (IOException ex) {
            return false;
        } catch (CertificateEncodingException ex) {
            return false;
        }

    }

    public boolean sendRegisterResponse(Long id_registro, String selloTemporal, byte[] sigRD, X509Certificate cert_firma_server) {
        try {
            writeLong(0L);
            writeLong(id_registro);
            writeString(selloTemporal);
            writeLong(sigRD.length);
            write(sigRD);
            byte[] temp = cert_firma_server.getEncoded();
            writeLong(temp.length);
            write(temp);
            flush();
            return true;
        } catch (IOException | CertificateEncodingException ex) {

        }
        return false;
    }

    public boolean sendRecoveryResponse(String id_registro, String ruta, String sello, byte[] firma_registrador, X509Certificate cert_firma_server, String docName) {

        try {
            //Escribimos una respuesta del tipo Registrar_documento.Response(0,idRegistro, sello Temporal, documento, SigRD, CertFirmaS)

            writeLong(0);
            flush();

            writeString(id_registro);
            flush();

            writeString(sello);
            flush();

            writeString(docName);

            File file = new File(ruta);
            InputStream in = new FileInputStream(file);
            long longitud = file.length();
            writeLong(longitud); //manda la longitud del fichero para saber cuanto tiene que leer
            flush();
            byte[] bytes = new byte[1024];
            int leidos;
            while ((leidos = in.read(bytes)) > 0) {
                write(Arrays.copyOfRange(bytes, 0, leidos));
            }
            flush();

            writeLong(firma_registrador.length);
            write(firma_registrador);
            flush();

            byte[] cert = cert_firma_server.getEncoded();
            writeLong(cert.length);
            write(cert);
            flush();

            return true;

        } catch (IOException ex) {
            return false;
        } catch (CertificateEncodingException ex) {
            return false;
        }

    }

    public boolean sendDocumentListRequest(ArrayList<DBData> lista) {

        try {

            /*enviamos el tamaño del arraylist para que en caso de tamaño 0,
            no tengamos que quedarnos escuchando en el lado del cliente*/
            write(lista.size());
            flush();

            for (int i = 0; i < lista.size(); i++) {

                /*idRegistro*/
                writeLong(lista.get(i).getId());
                flush();
                /*idPropietario*/
                writeString(lista.get(i).getUsuario());
                flush();
                /*nombreDoc*/
                writeString(lista.get(i).getNombre());
                flush();
                /*selloTemporal*/
                writeString(lista.get(i).getSello());
                flush();

                if (i == (lista.size() - 1)) {
                    write(255);
                    System.out.println("Es el último");
                    flush();
                } else {
                    write(1);
                    System.out.println("No es el último");
                    flush();
                }
            }

            return true;

        } catch (IOException e) {

        }
        return false;
    }
}
