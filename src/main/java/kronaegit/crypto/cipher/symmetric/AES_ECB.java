package kronaegit.crypto.cipher.symmetric;

import java.security.GeneralSecurityException;

@Deprecated
public class AES_ECB extends GeneralSymmetricEncryption {
    public AES_ECB(byte[] key) throws GeneralSecurityException {
        super("AES/ECB/PKCS5Padding", key);
    }
}