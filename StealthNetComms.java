/***********************************************************************************
 * ELEC5616
 * Computer and Network Security, The University of Sydney
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetComms.java
 * AUTHORS:         Stephen Gould, Matt Barrie, Ryan Junee
 * DESCRIPTION:     Implementation of StealthNet Communications for ELEC5616
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0
 * IMPLEMENTS:      initiateSession();
 *                  acceptSession();
 *                  terminateSession();
 *                  sendPacket();
 *                  recvPacket();
 *                  recvReady();
 *
 * REVISION HISTORY:
 *
 **********************************************************************************/

/* Import Libraries **********************************************************/

import java.net.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.interfaces.*;
import java.io.*;
import java.math.*;

/* StealthNetComms class *****************************************************/

public class StealthNetComms {
    public static final String SERVERNAME = "localhost";
    public static final int SERVERPORT = 5616;
    
    private Socket commsSocket;             // communications socket
    private PrintWriter dataOut;            // output data stream
    private BufferedReader dataIn;          // input data stream

    private SecretKey sKey;
    private TripleDESEncrypter encrypter;
    private SecureRandom random;
    
    public byte[] currentNonce;

    
    public StealthNetComms() {
        commsSocket = null;
        dataIn = null;
        dataOut = null;
    }

    protected void finalize() throws IOException {
        if (dataOut != null)
            dataOut.close();
        if (dataIn != null)
            dataIn.close();
        if (commsSocket != null)
            commsSocket.close();
    }

    public boolean initiateSession(Socket socket) {
        try {
            commsSocket = socket;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(
                commsSocket.getInputStream()));
            this.sendKeyInfo();
        } catch (Exception e) {
            System.err.println("Connection terminated.");
            System.exit(1);
        }
        return true;
    }

    public boolean acceptSession(Socket socket) {
        try {
            commsSocket = socket;
            PublicKey publicKey;
            dataOut = new PrintWriter(commsSocket.getOutputStream(), true);
            dataIn = new BufferedReader(new InputStreamReader(
                commsSocket.getInputStream()));
            //Receives key info and extracts useful information from it
            byte[] publicKeyBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(dataIn.readLine());
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFact = KeyFactory.getInstance("DH");
            publicKey = keyFact.generatePublic(x509KeySpec);
            
            BigInteger p = ((DHKey) publicKey).getParams().getP();
            BigInteger g = ((DHKey) publicKey).getParams().getG();
            int l = ((DHKey) publicKey).getParams().getL();
            
            // Use the values to generate a key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
            keyGen.initialize(dhSpec);
            KeyPair keypair = keyGen.generateKeyPair();

            // Get the generated public and private keys
            PrivateKey privatekey = keypair.getPrivate();
            PublicKey publickey = keypair.getPublic();
            
            // Send the public key bytes to the other party...
            byte[] publickeyBytes = publickey.getEncoded();
            dataOut.println(javax.xml.bind.DatatypeConverter.printBase64Binary(publickeyBytes));
         	
            // Prepare to generate the secret key with the private key and public key of the other party
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(privatekey);
            ka.doPhase(publicKey, true);
            
            // Specify the type of key to generate;
            String algorithm = "DESede";
            
            // Generate the secret key
            SecretKey secretKey = ka.generateSecret(algorithm);
            byte [] secretBytes = ka.generateSecret();
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.reset();
            md.update(secretBytes);
            byte [] secretKeyBytes = secretKey.getEncoded();
            byte [] digest = md.digest();
            System.arraycopy(secretKeyBytes, 0, digest, digest.length, secretKeyBytes.length);
            SecretKeySpec secretKeyFromBytes = new SecretKeySpec(digest, algorithm);
            sKey = secretKeyFromBytes;
            encrypter = new TripleDESEncrypter(sKey);

            SecureRandom r = new SecureRandom();
            byte [] seed = new byte [256];
            r.nextBytes(seed);
            dataOut.println(encrypter.encrypt(javax.xml.bind.DatatypeConverter.printBase64Binary(seed)));
            random = new SecureRandom(seed);
        }catch (InvalidKeySpecException i){
        	System.err.println(i);
        	System.exit(1);
        }catch (NoSuchAlgorithmException n){
        	System.err.println(n);
        	System.exit(1);
        }catch (InvalidKeyException i){
        	System.err.println(i);
        	System.exit(1);
    	}catch (Exception e) {
            System.err.println("Connection terminated.");
            System.exit(1);
        }
        return true;
    }

    public boolean terminateSession() {
        try {
            if (commsSocket == null)
                return false;
            dataIn.close();
            dataOut.close();
            commsSocket.close();
            commsSocket = null;
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public boolean sendPacket(byte command) {
        return sendPacket(command, new byte[0]);
    }

    public boolean sendPacket(byte command, String data) {
        System.out.println("String data: " + data);
        return sendPacket(command, data.getBytes());
    }

    public boolean sendPacket(byte command, byte[] data) {
    	return sendPacket(command, data, data.length);
    }

    public boolean sendPacket(byte command, byte[] data, int size) {
        StealthNetPacket pckt = new StealthNetPacket();
        pckt.command = command;
        pckt.data = new byte[size];
        System.arraycopy(data, 0, pckt.data, 0, size);
        return sendPacket(pckt);
    }

    public boolean sendPacket(StealthNetPacket pckt) {
        if (dataOut == null)
            return false;
        String str = pckt.toString();
        //Generates the MAC for the message
        try {
        	//TODO: prepend nonce to string, 8 sequential bytes fed through PRNG, covers 10^8 messages
        	SecureRandom rand = new SecureRandom();
        	byte [] random = rand.generateSeed(6);
        	
    		Mac mac = Mac.getInstance("HmacMD5");
    	   	mac.init(sKey);
    	   	byte[] utf8 = str.getBytes("UTF8");
    	    byte[] digest = mac.doFinal(utf8);
    	    String digestB64 = javax.xml.bind.DatatypeConverter.printBase64Binary(digest);
      	    str = str.concat(digestB64);
    	} catch (NoSuchAlgorithmException e) {
    	} catch (InvalidKeyException e) {
    	} catch (UnsupportedEncodingException e) {
    	}
        dataOut.println(encrypter.encrypt(str, random));
        return true;
    }

    public StealthNetPacket recvPacket() throws IOException {
        StealthNetPacket pckt = null;
        String str = dataIn.readLine();
        String decrypted =  encrypter.decrypt(str, random);
        String MAC = decrypted.substring(decrypted.length()-24);
        String message = decrypted.substring(0, decrypted.length() - 24);
        try {
        	//Checks the MAC against the message
    		Mac mac = Mac.getInstance("HmacMD5");
    	   	mac.init(sKey);
    	   	byte[] utf8 = message.getBytes("UTF8");
    	    byte[] digest = mac.doFinal(utf8);
    	    String digestB64 = javax.xml.bind.DatatypeConverter.printBase64Binary(digest);
    	    if (digestB64.equals(MAC)){
    	    } else {
    	    	System.out.println("String has been altered, communication line unsafe.");
    	    	System.exit(1);
    	    }
        } catch (NoSuchAlgorithmException e) {
    	} catch (InvalidKeyException e) {
    	} catch (UnsupportedEncodingException e) {
    	}
        pckt = new StealthNetPacket(message);
        return pckt;
    }

    public boolean recvReady() throws IOException {
/*
        System.out.println("Connected: " + commsSocket.isConnected());
        System.out.println("Closed: " + commsSocket.isClosed());
        System.out.println("InClosed: " + commsSocket.isInputShutdown());
        System.out.println("OutClosed: " + commsSocket.isOutputShutdown());
*/
        return dataIn.ready();
    }

    
    public static String genDhParams() {
        try {
            // Create the parameter generator for a 1024-bit DH key pair
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);

            // Generate the parameters
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

            // Return the three values in a string
            return ""+dhSpec.getP()+","+dhSpec.getG()+","+dhSpec.getL();
        } catch (NoSuchAlgorithmException e) {
        } catch (InvalidParameterSpecException e) {
        }
        return null;
    }
    
    public void sendKeyInfo() {
    	String[] values = genDhParams().split(",");
    	BigInteger p = new BigInteger(values[0]);
    	BigInteger g = new BigInteger(values[1]);
    	int l = Integer.parseInt(values[2]);

    	try {
    		// Use the values to generate a key pair
    		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    		DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
    		keyGen.initialize(dhSpec);
    		KeyPair keypair = keyGen.generateKeyPair();
   	    	
    		// Get the generated public and private keys
  	    	PrivateKey privateKey = keypair.getPrivate();
   	    	PublicKey publicKey = keypair.getPublic();
   	    	
   	    	// Send the public key bytes to the other party
   	    	byte[] publicKeyBytes = publicKey.getEncoded();
   	    	dataOut.println(javax.xml.bind.DatatypeConverter.printBase64Binary(publicKeyBytes));
   	    	
   	    	//Get the publicKey from the other party
   	    	byte[] publickeyBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(dataIn.readLine());
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publickeyBytes);
            KeyFactory keyFact = KeyFactory.getInstance("DH");
            publicKey = keyFact.generatePublic(x509KeySpec);
            
            // Prepare to generate the secret key with the private key and public key of the other party
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(privateKey);
            ka.doPhase(publicKey, true);
            
            // Specify the type of key to generate;
            String algorithm = "DESede";
            
            // Generate the secret key
            SecretKey secretKey = ka.generateSecret(algorithm);
            byte [] secretBytes = ka.generateSecret();
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.reset();
            md.update(secretBytes);
            byte [] secretKeyBytes = secretKey.getEncoded();
            byte [] digest = md.digest();
            System.arraycopy(secretKeyBytes, 0, digest, digest.length, secretKeyBytes.length);
            SecretKeySpec secretKeyFromBytes = new SecretKeySpec(digest, algorithm);
            sKey = secretKeyFromBytes;
            encrypter = new TripleDESEncrypter(sKey);
            
            String randomSeed = dataIn.readLine();
            byte[] seed = javax.xml.bind.DatatypeConverter.parseBase64Binary(encrypter.decrypt(randomSeed));
            random = new SecureRandom(seed);
   	    	return;
    	} catch (InvalidKeySpecException e) {
    	} catch (InvalidKeyException e) {
    	} catch (java.security.InvalidAlgorithmParameterException e) {
    	} catch (java.security.NoSuchAlgorithmException e) {
    	} catch (IOException e) {
    	}
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetComms.java
 *****************************************************************************/
 
