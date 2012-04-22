
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class TripleDESEncrypter {
    SecretKey key;

    TripleDESEncrypter(SecretKey key) {
    	this.key = key;
    }

    public String encrypt(String str) {
    	return encrypt(str, (SecureRandom)null);
    }
    public String encrypt(String str, SecureRandom r) {
        try {
        	Cipher ecipher;
            // Encode the string into bytes using utf-8
            byte[] utf8 = str.getBytes("UTF8");

            try {
	            if (r != null) {
	            	byte[] iv = new byte[8];
	            	r.nextBytes(iv);
	            	ecipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
	            	ecipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
	            } else {
	            	ecipher = Cipher.getInstance("DESede");
	            	ecipher.init(Cipher.ENCRYPT_MODE, key);
	            }
            } catch (GeneralSecurityException ex) {
            	System.out.println("Error, error! Danger someone something.");
            	ex.printStackTrace();
            	return null;
            }
            
            // Encrypt
            byte[] enc = ecipher.doFinal(utf8);

            // Encode bytes to base64 to get a string
            return javax.xml.bind.DatatypeConverter.printBase64Binary(enc);
        } catch (javax.crypto.BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        } catch (UnsupportedEncodingException e) {
        }
        return null;
    }

    public String decrypt(String str) {
    	return decrypt(str, (SecureRandom) null);
    }
    public String decrypt(String str, SecureRandom r) {
        try {
        	Cipher ecipher;
            // Decode base64 to get bytes
            byte[] dec = javax.xml.bind.DatatypeConverter.parseBase64Binary(str);

            try {
	            if (r != null) {
	            	byte[] iv = new byte[8];
	            	r.nextBytes(iv);
	            	ecipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
	            	ecipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
	            } else {
	            	ecipher = Cipher.getInstance("DESede");
	            	ecipher.init(Cipher.DECRYPT_MODE, key);
	            }
            } catch (GeneralSecurityException ex) {
            	System.out.println("Error, error! Danger someone something.");
            	ex.printStackTrace();
            	return null;
            }
            
            // Decrypt
            byte[] utf8 = ecipher.doFinal(dec);

            // Decode using utf-8
            return new String(utf8, "UTF8");
        } catch (javax.crypto.BadPaddingException e) 
        {
        } catch (IllegalBlockSizeException e) {
        } catch (UnsupportedEncodingException e) {
        }
        return null;
    }
}
