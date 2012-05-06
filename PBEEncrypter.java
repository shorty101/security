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
	
	private void setSalt(){
		r.nextBytes(salt);
	}
    
    
    // Iteration count
    private int count = 20;
    
    public void encrypt(File file){
    	try{
    		byte[] cleartext = new byte[(int) file.length()];
    		FileInputStream fileInputStream = new FileInputStream(file);
    		fileInputStream.read(cleartext);
    		setSalt();
    		// Create PBE parameter set
    		pbeParamSpec = new PBEParameterSpec(salt, count);

    		// Prompt user for encryption password.
    		// Collect user password as char array (using the
    		// "readPasswd" method from above), and convert
    		// it into a SecretKey object, using a PBE key
    		// factory.
    		System.out.print("Enter encryption password:  ");
    		System.out.flush();
    		pbeKeySpec = new PBEKeySpec(readPasswd(System.in));
    		keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
    		SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
    	
    		// Create PBE Cipher
    		Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndTripleDES");

    		// Initialize PBE Cipher with key and parameters
    		pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

    		Mac mac = Mac.getInstance("HmacMD5");
    		mac.init(pbeKey);
    		byte[] utf8 = cleartext;
			byte[] digest = mac.doFinal(utf8);
			System.out.println("MAC: " + javax.xml.bind.DatatypeConverter
					.printBase64Binary(digest));
			byte[] clearMAC = new byte [cleartext.length + digest.length];
			System.arraycopy(cleartext, 0, clearMAC, 0, cleartext.length);
			System.arraycopy(digest, 0, clearMAC, cleartext.length, digest.length);
    		
    		// Encrypt the cleartext 		
    		byte[] ciphertext = pbeCipher.doFinal(clearMAC);
    		
    		byte[] cipherplussalt = new byte[ciphertext.length + 8];
    		System.arraycopy(salt, 0, cipherplussalt, 0, salt.length);
    		System.arraycopy(ciphertext, 0, cipherplussalt, salt.length, ciphertext.length);
    		File newFile = new File("C:/Users/Andrew/Desktop/EncryptedTest.txt");
    		newFile.createNewFile();
    		FileOutputStream fos = new FileOutputStream("C:/Users/Andrew/Desktop/EncryptedTest.txt");
    		fos.write(cipherplussalt);
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
    
    public void decrypt(File file){
    	try{
    		byte[] cipherlesssalt = new byte[(int) file.length() - 8];
    		byte[] ciphertext = new byte[(int) file.length()];
    		byte[] filesalt = new byte[8];
    		FileInputStream fileInputStream = new FileInputStream(file);
    		fileInputStream.read(ciphertext);
    		System.arraycopy(ciphertext, 0, filesalt, 0, 8);
    		System.arraycopy(ciphertext, 8, cipherlesssalt, 0, cipherlesssalt.length);
    		pbeParamSpec = new PBEParameterSpec(filesalt, count);
    		

    		// Prompt user for encryption password.
    		// Collect user password as char array (using the
    		// "readPasswd" method from above), and convert
    		// it into a SecretKey object, using a PBE key
    		// factory.
    		System.out.print("Enter decryption password:  ");
    		System.out.flush();
    		pbeKeySpec = new PBEKeySpec(readPasswd(System.in));
    		keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
    		SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
	
    		// Create PBE Cipher
    		Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
    		
    		// Initialize PBE Cipher with key and parameters
    		pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
		
    		byte[] clearMAC = pbeCipher.doFinal(cipherlesssalt);
    		byte[] MAC = new byte[16];
    		byte[] cleartext = new byte[clearMAC.length - 16];
    		System.arraycopy(clearMAC, clearMAC.length - 16, MAC, 0, 16);
    		System.arraycopy(clearMAC, 0, cleartext, 0, clearMAC.length - 16);
    		
    		Mac mac = Mac.getInstance("HmacMD5");
			mac.init(pbeKey);
			byte[] digest = mac.doFinal(cleartext);
			String expectedMAC = javax.xml.bind.DatatypeConverter.printBase64Binary(digest);
			String actualMAC = javax.xml.bind.DatatypeConverter.printBase64Binary(MAC);
			if (expectedMAC.equals(actualMAC)) {
			} else {
				System.out
						.println("File has been altered, things are unsafe yo.");
				System.exit(1);
			}
    		
    		File newFile = new File("C:/Users/Andrew/Desktop/DecryptedTest.txt");
    		newFile.createNewFile();
    		FileOutputStream fos = new FileOutputStream("C:/Users/Andrew/Desktop/DecryptedTest.txt");
    		fos.write(cleartext);
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
    
    /**
     * Reads user password from given input stream.
     */
    public char[] readPasswd(InputStream in) throws IOException {
        char[] lineBuffer;
        char[] buf;
        int i;

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