package kronaegit.crypto.cipher;

import java.security.GeneralSecurityException;

public interface Cipher {
    byte[] encrypt(byte[] data) throws GeneralSecurityException;
    byte[] decrypt(byte[] data) throws GeneralSecurityException;
}
