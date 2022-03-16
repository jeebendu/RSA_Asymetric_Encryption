
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class AsymmetricMain {

	private static final String ALGORITHM = "RSA";
	private static final String PVTKEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCa1OwhIXq10pykhtCap/stVCL0 X/1VyyeAl82HXEHotvw8F6TR8y9AsARdgSpHn6ozPaHSvo39QqTPvni065iaYidXFt4rR6dLrQ8S Ar1edbVQ/L//DCSQPQezmr0fL88R2oMO/MdPVPLlnwTJMXhMCQTnKydD/otShjSfpd9FVqII9BGh MR68pUBCtLgNcmn1YgBqXUyUGWahFbPsOAn0yRD+/28Y3xDYu3y3rNINITNf2bS2GKbmhKV1QLjp 0v7N5VppWBrrYlRSmlMyf2/1ChZPWEPUjdC117aR+PDY6t6dPtcap/pCxU4vQo1oIZBre1AEfoCe mt5bNj4yB30rAgMBAAECggEAeXfn1EomsfSMTYsyptJ4fORQE/YmkqMx13HAnZwkXQUJt7844Dlv 7cjpc838tHovlcmZZfN3A6TAFfcxTYazjxLIGEvpenzZY8ZeV1vs4ulnmSThH5+QI9StcRtJmejx A+mw/hYT60oS0VBC+fCklspQnWc+g9pzxQdiy4jfM8534yjv8FnFQqRxuqAZfbJraSx5E+nT3XSt IrLriMoKsNaLSzXn+RulGJndxRmcZ63j+rmoiEPxl9nrU0S/ZwLfvuaCv1wy7kuJB80Gfc8W3N7m 8sq5o8pAqxRe6nz1WnI5EabArSyysOOeZdXC9lt3liLUMy2EO3QYX7chiewdWQKBgQDzLB90HI5H o1pNzPA/SNVD1pZIENtgCI+ssrJymjwZNAZBP8OKYCbygmXsO3cwTvxJ7F3d0kif+aa6ndjgU+9B 71z/QZD81pKmbTHqvOU/ceEEP02DufIANaUPzR/ZRAtzgRmW3o1O2qQu7uZyFQAbgqh9sci3NqTb f2FfvMfLvQKBgQCi/9HJZHZwSdhpRVEYfQPVCa4Wmhd/PNc7nWCrex0RpTxCx7ov67O4kDnwRKVa 6en2D2GDgB0nZRq54tURrAe+J63gEqghlEI8kgC3jZazZyTtyVm4vL+Sb0ssadc+47LnGtoR6ibE +LId5RPKmmTwR0UUgVDZOtQwZf+xYIXHBwKBgQCvFtH+9KCtjDz1T96ccoC8O8IxWZHbb86jdndu dQdYzlDConrVI65nZuSkV5zWN8kIIRzlHwgTx9n4/Lavrz/Spdq8ICWZJ5aoJm+OqTwXlpOCT2Is urI43GdhHT0VXx0vqYEXVF9Cq8MT2AgtlFljdYyEFIKFCN9i/DDMkkz5sQKBgHm1OMj+2az4hr38 AxSc7EqbYsD/qAHaxP9/gJoqYEc3sOpQRgbYISbzkj+Ekk9zD74qN+6/r4Ul6jHYXK5IXLOw3xTL +XyxPlAJ2L013MvyfVGMIhFd5lGKBoCQOyd7T69ejmwIAZDb/etyjDeg1zPOk5c/A8ZgNeY5kxW3 88vrAoGBAIfCKxtchHtCDj0mp+mBmXUCxzywMJgHfdnBXd1McUdeJS0ExTNKifY3YESCQdwfVgFX 681wzsNdENQpGrN1VF47zZvra33/2cwy2eGB1wOb9wDuJiYwZWV5uTkvaf3q9+N8m03V9gJrR4tj wXnJZOeA1/4gjkmWdzoTCg0zO1LT";
	private static final String PUBKEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmtTsISF6tdKcpIbQmqf7LVQi9F/9VcsngJfNh1xB6Lb8PBek0fMvQLAEXYEqR5+qMz2h0r6N/UKkz754tOuYmmInVxbeK0enS60PEgK9XnW1UPy//wwkkD0Hs5q9Hy/PEdqDDvzHT1Ty5Z8EyTF4TAkE5ysnQ/6LUoY0n6XfRVaiCPQRoTEevKVAQrS4DXJp9WIAal1MlBlmoRWz7DgJ9MkQ/v9vGN8Q2Lt8t6zSDSEzX9m0thim5oSldUC46dL+zeVaaVga62JUUppTMn9v9QoWT1hD1I3Qtde2kfjw2OrenT7XGqf6QsVOL0KNaCGQa3tQBH6AnpreWzY+Mgd9KwIDAQAB";

	// Generating public & private keys
	// using RSA algorithm.
	public static KeyPair generateRSAKkeyPair() throws Exception {
		SecureRandom secureRandom = new SecureRandom();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);

		keyPairGenerator.initialize(2048, secureRandom);
		return keyPairGenerator.generateKeyPair();
	}

	// Encryption function which converts
	// the plainText into a cipherText
	// using private Key.
	public static byte[] encrypt(String plainText, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance(ALGORITHM);

		cipher.init(Cipher.ENCRYPT_MODE, privateKey);

		return cipher.doFinal(plainText.getBytes());
	}

	// Decryption function which converts
	// the ciphertext back to the
	// original plaintext.
	public static String decrypt(byte[] cipherText, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance(ALGORITHM);

		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] result = cipher.doFinal(cipherText);

		return new String(result);
	}

	public static byte[] encrypt(String plainText, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(plainText.getBytes());
	}

	public static String decrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		byte[] decryptedBytes = cipher.doFinal(cipherText);

		return new String(decryptedBytes);
	}

	// Driver code
	public static void main(String args[]) throws Exception {
		b2f();

	}

	private static void f2b(String cipherText) {
		try {
			
			byte[] encodedPublicKey = Base64.getDecoder().decode((PUBKEY.replace(" ", "").getBytes()));
			PublicKey publicKey = getPublicKey(encodedPublicKey);
			String decryptedText = decrypt(Base64.getDecoder().decode(cipherText), publicKey);
			System.out.println("Public : The decrypted text is: " + decryptedText);
			
			byte[] dataEncByPublicKey = encrypt(decryptedText, publicKey);
			System.out.print("Public : The Encrypted Text is: ");
			System.out.println(Base64.getEncoder().encodeToString(dataEncByPublicKey));
			
			backendPro(Base64.getEncoder().encodeToString(dataEncByPublicKey));
			//backendPro(DatatypeConverter.printHexBinary(dataEncByPublicKey));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static void backendPro(String cipherText) {
		try {
			
		byte[] encodedPrivateKey = Base64.getDecoder().decode((PVTKEY.replace(" ", "").getBytes()));
		PrivateKey privateKey = getPrivateKey(encodedPrivateKey);
		String decryptedText = decrypt(Base64.getDecoder().decode(cipherText), privateKey);
		System.out.println("Backend : The decrypted text is: " + decryptedText);
		
		
		
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private static void b2f() {
		try {
			/*
			KeyPair keypair = generateRSAKkeyPair();
			
			System.out.println ("-----BEGIN PRIVATE KEY-----");
	        System.out.println (Base64.getMimeEncoder().encodeToString( keypair.getPrivate().getEncoded()));
	        System.out.println ("-----END PRIVATE KEY-----");
	        System.out.println ("-----BEGIN PUBLIC KEY-----");
	        System.out.println (Base64.getMimeEncoder().encodeToString( keypair.getPublic().getEncoded()));
	        System.out.println ("-----END PUBLIC KEY-----");
*/
			String plainText = "This is the PlainText " + "I want to Encrypt using RSA.";
			
			
			byte[] encodedPublicKey = Base64.getDecoder().decode((PUBKEY.replace(" ", "").getBytes()));
			byte[] encodedPrivateKey = Base64.getDecoder().decode((PVTKEY.replace(" ", "").getBytes()));

			PublicKey publicKey = getPublicKey(encodedPublicKey);
		    PrivateKey privateKey = getPrivateKey(encodedPrivateKey);
		    
			byte[] cipherText = encrypt(plainText, privateKey);

			//System.out.println( "The Public Key is: " + DatatypeConverter.printHexBinary(keypair.getPublic().getEncoded()));

			//System.out.println( "The Private Key is: " + DatatypeConverter.printHexBinary(keypair.getPrivate().getEncoded()));

			System.out.print("Backend :The Encrypted Text is: ");

			System.out.println(Base64.getEncoder().encodeToString(cipherText));
			
			
			String decryptedText = decrypt(cipherText, publicKey);

			System.out.println("Backend : The decrypted text is: " + decryptedText);

			f2b(Base64.getEncoder().encodeToString(cipherText));

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public static byte[] hexStringToByteArray(String hexString) {
	    byte[] bytes = new byte[hexString.length() / 2];

	    for(int i = 0; i < hexString.length(); i += 2){
	        String sub = hexString.substring(i, i + 2);
	        Integer intVal = Integer.parseInt(sub, 16);
	        bytes[i / 2] = intVal.byteValue();
	        String hex = "".format("0x%x", bytes[i / 2]);
	    }
	    return bytes;
	}
	
	
	
    public static PublicKey getPublicKey(byte[] pk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        PublicKey pub = kf.generatePublic(publicKeySpec);
        return pub;
    }

    public static PrivateKey getPrivateKey(byte[] privk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(privk);
        //KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        //PrivateKey privateKey = kf.generatePrivate(privateKeySpec);
        
        
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privk);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

	private static RSAPublicKey getPublicKey(String publicKey) {
		try {
			byte[] decoded = Base64.getDecoder().decode(publicKey);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
			RSAPublicKey generatePublic = (RSAPublicKey) kf.generatePublic(spec);
			return generatePublic;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	private static RSAPrivateKey getPrivateKey(String privateKey) {
		try {
			byte[] decoded = Base64.getDecoder().decode(privateKey);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
			RSAPrivateKey generatePrivate = (RSAPrivateKey) kf.generatePrivate(spec);
			return generatePrivate;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
