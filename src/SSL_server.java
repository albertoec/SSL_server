
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;

import Utils.DB.DBData;
import Utils.DB.DBException;
import Utils.DB.DBHandler;
import Utils.cipher.cifrador;

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

	public static final String ENTRY_AES = "aes_secret_key";
	public static final String ENTRY_DES = "des_secret_key";
	public static final String ENTRY_FIRMA = "servidor-firma-rsa";
	public static final String ENTRY_CLAVE = "servidor-auth-rsa";
	public static final String FAIL_CERT = "CERTIFICADO INCORRECTO";
	public static final String FAIL_SIGN = "FIRMA INCORRECTA";
	public static final String OK = "OK";
	public static final String FAIL_INTERNO = "FALLO INTERNO DEL SERVIDOR";
	private static final String CONTRASEÑA = "seguridadproyect";
	public static DBHandler HANDLER;
	public static cifrador Cifrador;

	public static void main(String[] args) {

		if (args.length != 5) {
			System.out.println(
					"Uso: SSL_server keyStoreFile contraseñaKeystore truststoreFile contraseñaTruststore algoritmoCifrado");
		}

		keyStore = args[0].trim();
		keyStorePass = args[1].trim();
		trustStore = args[2].trim();
		trustStorePass = args[3].trim();

		try {

			new SSL_server().definirKeyStores();

			SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSL_server
					.getServerSocketFactory("TLS");
			SSLServerSocket socket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT);

			// INICIALIZANDO EL CIFRADOR.
			System.out.println("Inicializando el cifrador.");
			Cifrador = new cifrador(trustStorePass, keyStore);
			System.out.println("Cifrador inicializado.");
			// creando handler de la base de datos
			System.out.println("Creando handler de la base de datos.");
			HANDLER = new DBHandler();
			DBData datitos = HANDLER.getData(2L);
			
			System.out.println("Handler creado con éxito.");

			System.out.println("*************************");
			System.out.println("* Servidor inicializado *");
			System.out.println("*************************");

			while (true) {

				Runnable thread = new Hilo((SSLSocket) socket.accept());
				new Thread(thread).start();
			}
		} catch (IOException ex) {
			Logger.getLogger(SSL_server.class.getName()).log(Level.SEVERE, null, ex);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void definirKeyStores() {

		// System.setProperty("javax.net.debug", "all");
		// ---- Almacenes mios -----------------------------
		// Almacen de claves
		System.setProperty("javax.net.ssl.keyStore", keyStore + ".jce");
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", keyStorePass);

		// Almacen de confianza
		System.setProperty("javax.net.ssl.trustStore", trustStore + ".jce");
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", trustStorePass);

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

	public static byte[] sign(String docPath, Long idRegistro, String sello, byte[] firmaCliente, String entry_alias)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException,
			UnrecoverableEntryException, InvalidKeyException, SignatureException, CertificateException {

		FileInputStream fmensaje = new FileInputStream(docPath);

		String provider = "SunJCE";
		String algoritmo = "SHA256withRSA";
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

		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(entry_alias,
				new KeyStore.PasswordProtection(key_password));
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

		// Para firmar primero pasamos el hash a los datos (metodo "update")
		// y despues firmamos el hash (metodo sign).
		byte[] firma;
		// primero el id del registro
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(idRegistro);
		signer.update(buffer.array());
		// segundo el sello temporal
		signer.update(sello.getBytes());
		// tercero el documento
		while ((longbloque = fmensaje.read(bloque)) > 0) {
			filesize = filesize + longbloque;
			signer.update(bloque, 0, longbloque);
		}
		// y cuarto y último la firma del documento
		signer.update(firmaCliente);
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

	public static boolean verify(String docPath, byte[] firma) throws FileNotFoundException, CertificateException,
			InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException, KeyStoreException {

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
		System.out.println((String) aliases.nextElement());
                
		while (aliases.hasMoreElements()) {

			FileInputStream fmensajeV = new FileInputStream(docPath);

			String alias = aliases.nextElement();

			// Obtener la clave publica del keystore
			PublicKey publicKey = ks.getCertificate(alias).getPublicKey();

			System.out.println("*** CLAVE PUBLICA ***");
			System.out.println(publicKey);

			// Obtener el usuario del Certificado tomado del KeyStore.
			// Hay que traducir el formato de certificado del formato del
			// keyStore
			// al formato X.509. Para eso se usa un CertificateFactory.
			byte[] certificadoRaw = ks.getCertificate(alias).getEncoded();
			ByteArrayInputStream inStream;
			inStream = new ByteArrayInputStream(certificadoRaw);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

			// Creamos un objeto para verificar, pasandole el algoritmo leido
			// del certificado.
			Signature verifier = Signature.getInstance(cert.getSigAlgName());
			System.out.println(cert.getSigAlgName());
			// Inicializamos el objeto para verificar
			verifier.initVerify(publicKey);

			while ((longbloque = fmensajeV.read(bloque)) > 0) {
				filesize = filesize + longbloque;
				verifier.update(bloque, 0, longbloque);
			}

			boolean resultado;
			System.out.println((String) aliases.nextElement());
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

	public static boolean verifyCert(byte[] certificado) throws Exception {

		KeyStore ks;
		ByteArrayInputStream inStream;
		PublicKey publicKey;
		char[] ks_password;

		ks_password = trustStorePass.toCharArray();
		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(trustStore + ".jce"), ks_password);

		// Obtener el certificado de un array de bytes
		// Obtener la clave publica del keystore
		// Obtener el certificado de un array de bytes
		inStream = new ByteArrayInputStream(certificado);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

		// Listamos los alias y después los recorremos en busca de un
		// certificado que valga
		Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {

			// Obtener la clave publica del keystore
			publicKey = ks.getCertificate(aliases.nextElement()).getPublicKey();

			try {

				cert.verify(publicKey);
				System.out.println("\nCertificado correcto");

				return true;

			} catch (InvalidKeyException e) {

			} catch (SignatureException ex) {

			} catch (Exception ex) {
				// capturar el resto de excepciones posibles para que no se
				// cuelgue el bucle por no haber capturado la excepcion
			}
		}

		System.out.println("Certificado incorrecto");
		return false;
	}

	/**
	 * 
	 * @param id_registro
	 * @param usuario
	 * @param temporal
	 * @param confidencialidad
	 * @return la ruta del fichero de destino o null en caso de ser confidencial
	 *         y no poderse cifrar
	 * @throws IOException
	 */
	public static String moveFile(long id_registro, String usuario, String temporal, boolean confidencialidad)
			throws IOException {
		// se crea la carpeta donde se almacenaran los documentos si no existe
		new File("documentos").mkdirs();
		String destino = "documentos/" + id_registro + "_" + usuario + ".sig";

		if (confidencialidad) {
			try {
				destino += ".cif";
				// cosas a hacer si es confidencial
				SSL_server.Cifrador.encrypt(temporal, destino);
				new File(temporal).delete();
			} catch (Exception ex) {
				new File(temporal).delete();
				return null;
			}

		} else {
			// no es confidencia -> no se cifra, se almacena tal cual
			Files.move(new File(temporal).toPath(), new File(destino).toPath(), StandardCopyOption.REPLACE_EXISTING);
		}
		return destino;
	}


	/**
	 * Al metodo le pasas el archivo en String a descifrar.
	 * 
	 * @return byte[] del archivo descifrado.
	 */
	public static byte[] decryptByte(String file)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, KeyStoreException,
			CertificateException, FileNotFoundException, IOException, UnrecoverableEntryException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SSL_server.Cifrador.setDescifrador();
		Cipher cipher = SSL_server.Cifrador.getCipher();

		byte[] decordedValue = DatatypeConverter.parseBase64Binary(file);
		byte[] cifrado = cipher.doFinal(decordedValue);

		return cifrado;
	}

}
