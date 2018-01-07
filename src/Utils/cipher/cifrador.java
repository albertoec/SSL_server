package Utils.cipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class cifrador {
	private Cipher cipher;
	private static final String IV = "SEGURIDADPROYECT";
	private SecretKeySpec key;

	public Cipher getCipher() {
		return cipher;
	}

	public void setCifrador()
			throws InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
	}

	public void setDescifrador()
			throws InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
	}

	public cifrador(String trustStorePass, String keyStore) throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, KeyStoreException, CertificateException, FileNotFoundException, IOException,
			UnrecoverableEntryException, InvalidKeyException, InvalidAlgorithmParameterException {
		char[] contraseñaKeyStore = trustStorePass.toCharArray();

		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
		KeyStore ks;
		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(keyStore ), contraseñaKeyStore);
		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) ks.getEntry("clavecifrado_server",
				new KeyStore.PasswordProtection(contraseñaKeyStore));
		System.out.println(pkEntry);
		SecretKey secretKey = pkEntry.getSecretKey();
		key = new SecretKeySpec(secretKey.getEncoded(), "AES");

	}

	/**
	 * Al metodo le pasas la ruta del archivo a cifrar.
	 * 
	 * @return String del archivo cifrado.
	 * @throws NoSuchPaddingException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws UnrecoverableEntryException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public void encrypt(String docPath, String docDest)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, KeyStoreException,
			CertificateException, FileNotFoundException, IOException, UnrecoverableEntryException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		setCifrador();

		File inputFile = new File(docPath);
		FileInputStream fmensaje = new FileInputStream(docPath);

		byte[] inputBytes = new byte[(int) inputFile.length()];
		fmensaje.read(inputBytes);
		for (int i = 0; i < inputBytes.length; i++) {
			System.out.print((char) inputBytes[i]);
		}
		byte[] cifrado = cipher.doFinal(inputBytes);
		FileOutputStream fcifrado = new FileOutputStream(new File(docDest));
		fcifrado.write(cifrado);
		fmensaje.close();
		fcifrado.close();
	}

	/**
	 * Al metodo le pasas la ruta del archivo a descifrar.
	 * 
     * @param docPath
     * @param docDestino
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.KeyStoreException
     * @throws java.security.cert.CertificateException
     * @throws java.io.FileNotFoundException
     * @throws java.security.UnrecoverableEntryException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
	 */
	public void decrypt(String docPath, String docDestino)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, KeyStoreException,
			CertificateException, FileNotFoundException, IOException, UnrecoverableEntryException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		setDescifrador();
		File inputFile = new File(docPath);
		FileInputStream fmensaje = new FileInputStream(docPath);
		byte[] inputBytes = new byte[(int) inputFile.length()];
		fmensaje.read(inputBytes);
		byte[] cifrado = cipher.doFinal(inputBytes);
		FileOutputStream out = new FileOutputStream(new File(docDestino));
		out.write(cifrado);
		out.close();
		fmensaje.close();
	}
}
