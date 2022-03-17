package com.rsa;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RsaMain {
	
	  private static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz1zqQHtHvKczHh58ePiRNgOyiHEx6lZDPlvwBTaHmkNlQyyJ06SIlMU1pmGKxILjT7n06nxG7LlFVUN5MkW/jwF39/+drkHM5B0kh+hPQygFjRq81yxvLwolt+Vq7h+CTU0Z1wkFABcTeQQldZkJlTpyx0c3+jq0o47wIFjq5fwIDAQAB";
	  private static String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALPXOpAe0e8pzMeHnx4+JE2A7KIcTHqVkM+W/AFNoeaQ2VDLInTpIiUxTWmYYrEguNPufTqfEbsuUVVQ3kyRb+PAXf3/52uQczkHSSH6E9DKAWNGrzXLG8vCiW35WruH4JNTRnXCQUAFxN5BCV1mQmVOnLHRzf6OrSjjvAgWOrl/AgMBAAECgYAgA0YHdZUFL7mmIvwuE/2+Vh7JVKRAhfM7ILNHQBx7wHkOqro9eWp8mGQhUeDvitWb1C4yizJK0Znkx/pqQtFZuoatUsggocjXFl86FElQwrBp08DvfKfd0bGgy0VTFQVmCtxiqhpAmC7xmXNZXfBD41rl9CKbFfZw05QC5BoQ0QJBAO7LSku97NgFBJQ+vbmVDonuvgnQjVNb7SnwrcpJHEUAGbaVq1a50jz+s6n39TOagASaW6pcY0uwiygYu6xDnkMCQQDAzIGNKFKomTI6djcOyHfQ1ZXqyDQ3guX6nHhzZnNHFF8ZD3fPyyIRSZ3JvPK5iEzJLhB7FRtyWkGcdXgJTWoVAkBfx9zKGqkYUJLwn2XcPWRygPdq2mMFb5bmPqqGu+KB7rNhoBD0nV4tpwALifCpPSxiLEPeRmZxoqN+dsU4KHsfAkAyQt4fK3zpAQ8MGJdf3jkGEzhC/bBHLHPB8pqgEvxIcnIcOWEVpbIa6aMd3Yk1fuftpnmbbLQ8CnWCUUlau3jFAkEAk6bOZIWhTYRwIZcwBdkpyLlbatQFoTTM3i444YutXt3FrFfaWBxge+eYKId+J4dCrt/EmHhSfWKEzHibf6N5Sg==";

	  private static String publicKey2 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8OQdBHxv9giRYb7SxI0wnWb3fpJACR0oTq+Ov5rcf0unljjW9fjZm6g2UOz2uz9C/KfTDhQ4jXKrW8ZtvhhNq2d7MvsV7hzbnLYq54ha8wyDFsCP1KT9UoAY0LI++KZMhr4P7m7/WSWkuyWXNr+AWXYlhk/U83xSEz161ayKO2wIDAQAB";
	  private static String privateKey2 = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALw5B0EfG/2CJFhvtLEjTCdZvd+kkAJHShOr46/mtx/S6eWONb1+NmbqDZQ7Pa7P0L8p9MOFDiNcqtbxm2+GE2rZ3sy+xXuHNuctirniFrzDIMWwI/UpP1SgBjQsj74pkyGvg/ubv9ZJaS7JZc2v4BZdiWGT9TzfFITPXrVrIo7bAgMBAAECgYAQtZdZRqO7e6QyXahS2WlXTPY4Nmm6ag2/dVD/OqIjJxwwjtFigyPdOwX9lMzDChvj/JuIB/XbWcyozEYaPnLWsIs8pADytM8ROvyVnEl/I3cUqtg6fbiToV3SQT3QxHzD4HIsgJVWLd6C+RM3+c9PL8jQyQIHJzlciUbICYFpwQJBANxHxnI0qcAEug5L9LYx1pRAGdJ+PzF2kFXKrpTwoVcBBVhv6htXrcS7WOEbjBB7GkJA5MBbIwOaS7XSI1B1XQsCQQDavnxYHLZrgdEoJEFOFBgJ0Z328+LwhWKcAt1fS/MYjbHNtDEPrrPzF5PsavJ2gTCYmVZKBJPGKHqiP1WiOZdxAkBiBYJ2EZ8z9iaA9CXJ6XWN9NRIyar/LL5fnth/KHDzEV46k1p+nk6SC7gqO6LhNpZhwxTH0AZNtRxZpU/XntIvAkEAjWVSRTaSKF4q0DLXT9wnSbmIzYgK6wSdoFEtvZr/kaCODXTrvcJlKb7U7J6ZCkcqHYoIwCHDT/T8iII+HXXy0QJBAILdzDpOOX8vjoZml49o0Fq6ylcyA/E7laK1Dbm7VvnV2r0UBLKiVswC9bFq2oJ1g7opJOE8++Oj89d66tMptdI=";

	
	public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
		frontendToBackend();
	}


	private static void frontendToBackend() {
		try {
            String encryptedString = Base64.getEncoder().encodeToString(RSAUtil.encrypt("Jeebendu", publicKey2));
            System.out.println(encryptedString);
            
            String decryptedString = RSAUtil.decrypt(encryptedString, privateKey2);
            System.out.println(decryptedString);
            
            String encryptedString3 = Base64.getEncoder().encodeToString(RSAUtil.encrypt("Jeebendu", privateKey2));
            System.out.println(encryptedString3);
            
            
            String encryptedString2 = "IrNnmPMhD1SAuDQTQKsX74yKXf4eCu9rLr/S7OfF06AN5CYla5v357fwR+xJt4H6k/1lFXcR0YawRsDQcp8IWi6UB+XOE805KCamEbUG9YTSk4+GUbviiCTQSC3Qz7VAqqJYO15bEBNpKB1sWiRojOTd3N8yVX7WA6p6JjoWa80=";
            
            System.out.println(encryptedString2);
            String decryptedString2 = RSAUtil.decrypt(encryptedString2, privateKey);
            System.out.println(decryptedString2);
            
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            System.err.println(e.getMessage());
        }

    
		
	}  

}
