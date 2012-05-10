import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.*;

public class PBEEncrypter {
	private PBEKeySpec pbeKeySpec;
	private PBEParameterSpec pbeParamSpec;
	private SecretKeyFactory keyFac;
	private SecureRandom r = new SecureRandom();
	private byte[] salt = new byte[8];
	private final static String cipherAlgorithm = "PBEWithMD5AndTripleDES";
	private final static String hmacAlgorithm = "HmacSHA1";
	private final static String defaultFile =System.getProperty("user.home") + File.separatorChar + "test.txt";
	private void setSalt(){
		r.nextBytes(salt);
	}

	// Iteration count
	private int count = 20;

	public void encrypt(String filename, String contents){
		// Prompt user for encryption password.
		// Collect user password as char array (using the
		// "readPasswd" method from above), and convert
		// it into a SecretKey object, using a PBE key
		// factory.
		System.out.print("Enter encryption password:  ");
		System.out.flush();
		String password = null;
		try {
			password = readPasswd(System.in).toString();
		} catch (IOException e) {
			e.printStackTrace();
		}
		encrypt(filename, contents.getBytes(), password);
	}
	
	public void encrypt(String filename, byte[] contents, String password){
		try{
			System.out.println(contents.toString());
			
			setSalt();
			// Create PBE parameter set
			pbeParamSpec = new PBEParameterSpec(salt, count);

			pbeKeySpec = new PBEKeySpec(password.toCharArray());
			keyFac = SecretKeyFactory.getInstance(cipherAlgorithm);
			SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

			// Create PBE Cipher
			Cipher pbeCipher = Cipher.getInstance(cipherAlgorithm);

			// Initialize PBE Cipher with key and parameters
			pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

			Mac mac = Mac.getInstance(hmacAlgorithm);
			mac.init(pbeKey);

			byte[] digest = mac.doFinal(contents);
			System.out.println(contents.toString());
			System.out.println("MAC: " + javax.xml.bind.DatatypeConverter.printBase64Binary(digest));
			byte[] clearMAC = new byte [contents.length + digest.length];
			System.arraycopy(contents, 0, clearMAC, 0, contents.length);
			System.arraycopy(digest, 0, clearMAC, contents.length, digest.length);
			System.out.println("ClearMAC: " + javax.xml.bind.DatatypeConverter.printBase64Binary(clearMAC));
			// Encrypt the cleartext 		
			byte[] ciphertext = pbeCipher.doFinal(clearMAC);

			byte[] cipherplussalt = new byte[ciphertext.length + 8];
			System.arraycopy(salt, 0, cipherplussalt, 0, salt.length);
			System.arraycopy(ciphertext, 0, cipherplussalt, salt.length, ciphertext.length);
			File newFile = new File(filename);
			newFile.createNewFile();
			FileOutputStream fos = new FileOutputStream(filename);
			fos.write(cipherplussalt);
//			fos.write(salt);
//			fos.write(b64);
			System.out.println("Salt: " + javax.xml.bind.DatatypeConverter.printBase64Binary(salt));
			System.out.println("Ciphertext: " + javax.xml.bind.DatatypeConverter.printBase64Binary(ciphertext));
			fos.close();
		} catch (IOException i) {
			System.out.println(i);
		} catch (NoSuchAlgorithmException n){
			System.out.println(n);
		} catch (InvalidKeySpecException k) {
			System.out.println(k);
		} catch (NoSuchPaddingException p){
			System.out.println(p);
		} catch (InvalidAlgorithmParameterException a){
			System.out.println(a);
		} catch (InvalidKeyException k){
			System.out.println(k);
		} catch (BadPaddingException p){
			System.out.println(p);
		} catch (IllegalBlockSizeException b){
			System.out.println(b);
		}
	}

	public byte[] decrypt(File file) {
		// Prompt user for encryption password.
		// Collect user password as char array (using the
		// "readPasswd" method from above), and convert
		// it into a SecretKey object, using a PBE key
		// factory.
		System.out.print("Enter decryption password:  ");
		System.out.flush();
		String password = "";
		try {
			password = readPasswd(System.in).toString();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return decrypt(file, password);
	}
	
	public byte[] decrypt(File file, String password) {
		try{
			System.out.println("DECRYPT");
			byte[] cipherlesssalt = new byte[(int) file.length() - 28];
			byte[] ciphertext = new byte[(int) file.length()];
			byte[] filesalt = new byte[8];
			char[] pwchar = password.toCharArray();
			FileInputStream fileInputStream = new FileInputStream(file);
			fileInputStream.read(ciphertext);
			System.arraycopy(ciphertext, 0, filesalt, 0, 8);
			System.arraycopy(ciphertext, 8, cipherlesssalt, 0, cipherlesssalt.length);
			String plain = javax.xml.bind.DatatypeConverter.printBase64Binary(cipherlesssalt);
			
			System.out.println("Cipherlesssalt: " + plain);
			System.out.println("Salt: " + javax.xml.bind.DatatypeConverter.printBase64Binary(filesalt));

			pbeParamSpec = new PBEParameterSpec(filesalt, count);

			pbeKeySpec = new PBEKeySpec(pwchar);
			
			keyFac = SecretKeyFactory.getInstance(cipherAlgorithm);
			SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

			// Create PBE Cipher
			Cipher pbeCipher = Cipher.getInstance(cipherAlgorithm);

			// Initialize PBE Cipher with key and parameters
			pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

			
			byte[] MAC = new byte[20];
			byte[] clearMAC = pbeCipher.doFinal(cipherlesssalt);
			System.out.println();
			byte[] cleartext = new byte[clearMAC.length - 20];
			System.arraycopy(clearMAC, clearMAC.length - 20, MAC, 0, 20);
			System.arraycopy(clearMAC, 0, cleartext, 0, clearMAC.length - 20);

			Mac mac = Mac.getInstance(hmacAlgorithm);
			mac.init(pbeKey);
			byte[] digest = mac.doFinal(cleartext);
			String expectedMAC = javax.xml.bind.DatatypeConverter.printBase64Binary(digest);
			System.out.println("ExpectedMAC: " + expectedMAC);
			String actualMAC = javax.xml.bind.DatatypeConverter.printBase64Binary(MAC);
			System.out.println("ActualMAC: " + actualMAC);
			if (expectedMAC.equals(actualMAC)) {
			} else {
				System.err.println("File "+file.toString()+ " has been altered");
				System.err.println("Hash " + actualMAC + " expected " + expectedMAC);
				System.err.println("CT " + plain);
				
				System.exit(1);
			}

			File newFile = new File(defaultFile);
			newFile.createNewFile();
			FileOutputStream fos = new FileOutputStream(defaultFile);
			fos.write(cleartext);
			fos.close();
			return cleartext;

		} catch (IOException i) {
			System.out.println(i);
		} catch (NoSuchAlgorithmException n){
			System.out.println(n);
		} catch (InvalidKeySpecException k) {
			System.out.println(k);
		} catch (NoSuchPaddingException p){
			System.out.println(p);
		} catch (InvalidAlgorithmParameterException a){
			System.out.println(a);
		} catch (InvalidKeyException k){
			System.out.println(k);
		} catch (BadPaddingException p){
			System.out.println(p);
		} catch (IllegalBlockSizeException b){
			System.out.println(b);
		}
		return null;
	}

	/**
	 * Reads user password from given input stream.
	 */
	public char[] readPasswd(InputStream in) throws IOException {
		char[] lineBuffer;
		char[] buf;
		//        int i;

		buf = lineBuffer = new char[128];

		int room = buf.length;
		int offset = 0;
		int c;

		loop:   while (true) {
			switch (c = in.read()) {
			case -1: 
			case '\n':
				break loop;

			case '\r':
				int c2 = in.read();
				if ((c2 != '\n') && (c2 != -1)) {
					if (!(in instanceof PushbackInputStream)) {
						in = new PushbackInputStream(in);
					}
					((PushbackInputStream)in).unread(c2);
				} else 
					break loop;

			default:
				if (--room < 0) {
					buf = new char[offset + 128];
					room = buf.length - offset - 1;
					System.arraycopy(lineBuffer, 0, buf, 0, offset);
					Arrays.fill(lineBuffer, ' ');
					lineBuffer = buf;
				}
				buf[offset++] = (char) c;
				break;
			}
		}

		if (offset == 0) {
			return null;
		}

		char[] ret = new char[offset];
		System.arraycopy(buf, 0, ret, 0, offset);
		Arrays.fill(buf, ' ');

		return ret;
	}
}