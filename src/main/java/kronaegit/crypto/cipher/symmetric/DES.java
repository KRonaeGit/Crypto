package kronaegit.crypto.cipher.symmetric;

import java.security.GeneralSecurityException;

@Deprecated
public class DES extends GeneralSymmetricEncryption {
    public DES(byte[] key) throws GeneralSecurityException {
        super("DES", key);
    }
}