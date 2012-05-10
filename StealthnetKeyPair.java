import java.io.File;
//import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
//import java.security.PrivateKey;
//import java.security.PublicKey;
import java.security.*;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;


public class StealthnetKeyPair {
	private String userID;
	private RSAPublicKey publicKey;
	private RSAPrivateKey privateKey;
	private String password;
	private static final String STRSEP = ",";
	private static final String HEADSEP = "!";
	
	// Deprecated, now use signature rather than exposing keys
//	public PublicKey getPublicKey() {return publicKey;}
//	public PrivateKey getPrivateKey() {return privateKey;}

	public String[] processContents(byte[] contents) {
		String contentsStr = contents.toString();
		String wanted = contentsStr.split(HEADSEP)[1];
		return wanted.split(STRSEP);
	}
	
	public StealthnetKeyPair(String filename, String password, StealthNetClient client) {
		PBEEncrypter crypt = new PBEEncrypter();
		File file = new File(filename);
		this.password = password;
		Tuple<String,String,String> account = new Tuple<String,String,String>(null,null,null);
		byte[] decrypted = null;
		String[] contents = {null, null, null, null};
		if (file.exists()) {
			System.out.println("Opening key file "+filename);
			decrypted = crypt.decrypt(file, password);
			contents = processContents(decrypted);
		}
		if (contents[0] == null) { //No user name
			userID = client.guiUserId();
		} else {
			userID = account.x;
			client.setUserId(userID);
		}
		if (contents[1] == null || contents[2] == null) { //Generate new key pair
			System.out.println("Generating new public/private key for " + filename);
			try {
				KeyPairGenerator kpg;
				kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048);
				KeyPair kp = kpg.genKeyPair();
				publicKey = (RSAPublicKey) kp.getPublic();
				privateKey = (RSAPrivateKey) kp.getPrivate();		
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		} else {
			BigInteger modulus   = new BigInteger(contents[1]);
			BigInteger privatebi = new BigInteger(contents[2]);
			BigInteger publicbi  = new BigInteger(contents[3]);
			RSAPrivateKeySpec pris = new RSAPrivateKeySpec(modulus, privatebi);
			RSAPublicKeySpec  pubs = new RSAPublicKeySpec(modulus, publicbi);
			
			try {
				KeyFactory kf = KeyFactory.getInstance("RSA");
				privateKey = (RSAPrivateKey) kf.generatePrivate(pris);
				publicKey  = (RSAPublicKey) kf.generatePublic(pubs);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			}
		}
	}
	
	public void saveKeys(String filename) {
		SecureRandom sr = new SecureRandom();
		String str = Long.toHexString(sr.nextLong()).substring(0, 10); //Random header
		str = str.concat(HEADSEP);

		str = str.concat(userID);
		str = str.concat(STRSEP);
		str = str.concat(privateKey.getModulus().toString());
		str = str.concat(STRSEP);
		str = str.concat(privateKey.getPrivateExponent().toString());
		str = str.concat(STRSEP);
		str = str.concat(publicKey.getPublicExponent().toString());
		System.out.println(str);
		PBEEncrypter crypt = new PBEEncrypter();

		crypt.encrypt(filename, str.getBytes(), password);
	}

	public boolean verifySig(String message, byte[] sig) {
		byte[] messageBytes = message.getBytes();
		try {
			Signature signature = Signature.getInstance("SHA1withRSA", "BC");
			signature.initVerify(publicKey);
			signature.update(messageBytes);
			return (signature.verify(sig));
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return false;
	}

	public byte[] signMessage(String message) {
		byte[] sigBytes = null;
		try {
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKey, new SecureRandom());
			sigBytes = signature.sign();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		return sigBytes;
	}
	
	public static void main(String[] args) {
		String filename = System.getProperty("user.home") + File.separatorChar + "test.txt";
//		StealthnetKeyPair skp = new StealthnetKeyPair(filename, "fruit", new StealthNetClient());
//		skp.saveKeys(filename);
		PBEEncrypter crypt = new PBEEncrypter();
		crypt.encrypt(filename, "hello".getBytes(), "Test");
		System.out.println(crypt.decrypt(new File(filename), "Test"));

	}
}
