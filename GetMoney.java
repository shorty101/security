import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class GetMoney {
	public Tuple<String, Integer, byte[]> getMoney(String userID, Integer n){
		SecureRandom r = new SecureRandom();
		byte[] b = new byte[40];
		r.nextBytes(b);
		return new Tuple<String, Integer, byte[]>(userID, n, generateHashChain(b, n));
	}
	
	public byte[] generateHashChain(byte[] number, int n){
		try {
			MessageDigest md;
			byte[] sha1hash = new byte[40];
			md = MessageDigest.getInstance("SHA-1");
			md.update(number);
			for(int i = 0; i < n; i++){
				sha1hash = md.digest();
				md.update(sha1hash);
			}
			return sha1hash;
		} catch(NoSuchAlgorithmException e){
			System.exit(1);
		}
		return null;
	}
}