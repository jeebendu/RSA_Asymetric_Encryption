
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
	private static final String PVTKEY = "308204BD020100300D06092A864886F70D0101010500048204A7308204A30201000282010100A9FA337450AAC6455A3E0F967AFBF3C72E598A195ECCC5E86EF0D3EA02DA3D1FDBC11E703073B4BC4A2FCF873B46501165805E1B9555F5392E9D82F6D3B2A91E898EFB4AE0BFD2B494363BD355C0425D2ED8AE0F655E822476DFC44F7467BE0F282AB2E00B3FDD903F91E3D71891D82F411B5ADCA7399D17DEAAD13A4B378BF13092FE50A42273BC90BA8AFFFC245517AF088A16346517821FF74A5D3FE6395FEEA6BD1DB31F5E4C1966CC96317599048B7DEED79A1920388D606BDF17C1DD450C99A0BF867E3DA1F33161FD8585A48B02514D23EC6C430A0AB368A4F56006663374D74681B84D88C23F322BF9298B55C3BEC11D294796FD739A279D624D3571020301000102820100497770E1E733C8BA950499EC2A7FD79FD172B5F3BD3BB8967BCCEF6B078C983ABADABF73321DF09229667CC63062759CEF480A64D5A8EF72A5A942BFB844524076A82C08F31735D502F265ED33F5033A0F536BF80F9247A1C717745BFB2E13C1AD54B7378AE531B87521735EB6A9E2CC99D15EF65BF8D4E34A447E6639B86A6D4114FF9504E1BCB603E93C820996CF588B22C7789AB1C0DEDF192AE886818A831889DDD58F6162C84E41A7A8DFBB2658FD1561D6035CA6617EFFBEA517C4349F4376628D5D5878B37769601633F6FFE38712697E6C6376FBF6BAA16C9013320EBCF45C5E8925549AFB3BB0478429B53298F795E3714369F4F31ABADEBBDFA9A102818100ECA539236C47FB27B359CA5E45AA13D18F9DD2C970CD0E13786829FD0E932AADB9BA4EA262D329F3E9FB90396D2F8DE2A38B8628893C1B2E846AE77AFBE9EA6B2AFE682D6D6790093356DCE8AAB3397C8D6D1F3A0B5B61DC66CACA12776F9DE42189376978721703C378D55CA5D4C8DE98B423D28940180F75736A517A808D7D02818100B7E11C8D6479725907AE4AA495FD17E7CD37779711E9299E5F9E822A6C8E762BD8020BD5029EA4F0271628013D3269BCB5302E8F2B97371FDB81B1AE1AED94CACE44DB72FDCBE1DA5352742AB511E65C75F553E1D634266E06E6CADD2A57DA0EB8FAEC18C7848549E89BC818008DAA95D722696C9D418AE4673E6B13B3E6DA0502818006E2CBE5D6F9C53A2382E25B99E5580C4A048AA4A7EE9F913B78B478139B7EAB6D731964AA4180C00337F9BB620CF730F81750410FB53B09407B27DF31435E39DE17670AA35B571A9D6ED2A0C68ECE866C4B179485CE13EBE8E5CFB977D63C9EEDC6E360E34B56961A7302AA5E7CF19760942552B401B47186B6640A98E8F2B50281800A2DE012C3B92567605179B85AC544098506C90C07E5CC7403FF165D9ADCD815DD435FBC4F04D144AA2543D9ADB598BCE59AE138F3C4CF3C683E69C3A5A1F956B0CC87097A9B4AC9774B5D3AF00329A97CAE341290751A9B84AE4A14AC3F68C6DFDEA42B4B003F10B45BCB5BE8CBEEE194A3470AC839D4A28844A050DAE8B0B102818100B2C9ECE364717C8F6A0D47FAB3A07DD90F5F0BFDC85AB315C6CF1DEB8341FAF281428586197685CF0F50C615B73238AE579298DBC1BBFA38DCD6CD4C33D961F945105B25520A55765B0055B4371B9B5EC6D09BC525D3B31048FF4E913FD4B57EE228807DD826BD7F433CB64752873B2053FC7EC286EC17FEEEC0394D1738CE49";
	private static final String PUBKEY = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100A9FA337450AAC6455A3E0F967AFBF3C72E598A195ECCC5E86EF0D3EA02DA3D1FDBC11E703073B4BC4A2FCF873B46501165805E1B9555F5392E9D82F6D3B2A91E898EFB4AE0BFD2B494363BD355C0425D2ED8AE0F655E822476DFC44F7467BE0F282AB2E00B3FDD903F91E3D71891D82F411B5ADCA7399D17DEAAD13A4B378BF13092FE50A42273BC90BA8AFFFC245517AF088A16346517821FF74A5D3FE6395FEEA6BD1DB31F5E4C1966CC96317599048B7DEED79A1920388D606BDF17C1DD450C99A0BF867E3DA1F33161FD8585A48B02514D23EC6C430A0AB368A4F56006663374D74681B84D88C23F322BF9298B55C3BEC11D294796FD739A279D624D35710203010001";

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
			PublicKey publicKey = getPublicKey(hexStringToByteArray(PUBKEY));
			String decryptedText = decrypt(hexStringToByteArray(cipherText), publicKey);
			System.out.println("The decrypted text is: " + decryptedText);
			
			byte[] encByPublicKey = encrypt(decryptedText, publicKey);
			System.out.print("The Encrypted Text is: ");
			System.out.println(DatatypeConverter.printHexBinary(encByPublicKey));
			
			backendPro(DatatypeConverter.printHexBinary(encByPublicKey));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static void backendPro(String cipherText) {
		try {
			
			
		PrivateKey privateKey = getPrivateKey(hexStringToByteArray(PVTKEY));
		String decryptedText = decrypt(hexStringToByteArray(cipherText), privateKey);
		System.out.println("The decrypted text is: " + decryptedText);
		
		
		PublicKey publicKey = getPublicKey(hexStringToByteArray(PUBKEY));
		String decryptedText2 = decrypt(hexStringToByteArray(cipherText), publicKey);
		System.out.println("The decrypted text is: " + decryptedText2);
		
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private static void b2f() {
		try {
			//KeyPair keypair = generateRSAKkeyPair();

			String plainText = "This is the PlainText " + "I want to Encrypt using RSA.";
			
			
			PublicKey publicKey = getPublicKey(hexStringToByteArray(PUBKEY));
		    PrivateKey privateKey = getPrivateKey(hexStringToByteArray(PVTKEY));
		    
			byte[] cipherText = encrypt(plainText, privateKey);

			//System.out.println( "The Public Key is: " + DatatypeConverter.printHexBinary(keypair.getPublic().getEncoded()));

			//System.out.println( "The Private Key is: " + DatatypeConverter.printHexBinary(keypair.getPrivate().getEncoded()));

			System.out.print("The Encrypted Text is: ");

			System.out.println(DatatypeConverter.printHexBinary(cipherText));
			
			
			String decryptedText = decrypt(cipherText, publicKey);

			System.out.println("The decrypted text is: " + decryptedText);

			f2b(DatatypeConverter.printHexBinary(cipherText));

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
