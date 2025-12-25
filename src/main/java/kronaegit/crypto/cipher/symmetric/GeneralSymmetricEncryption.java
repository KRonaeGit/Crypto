package kronaegit.crypto.cipher.symmetric;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class GeneralSymmetricEncryption extends SymmetricEncryption<SecretKeySpec> {
    private final String algorithm;
    private final Cipher cipher;

    public GeneralSymmetricEncryption(String algorithm, byte[] key) throws GeneralSecurityException {
        super(key);
        this.algorithm = algorithm;
        this.cipher = Cipher.getInstance(algorithm);
    }

    @Override
    protected SecretKeySpec toKeyObject(byte[] key) throws GeneralSecurityException {
        return new SecretKeySpec(key, algorithm);
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        synchronized (cipher) {
            cipher.init(Cipher.ENCRYPT_MODE, getKey());
            return cipher.doFinal(data);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) throws GeneralSecurityException {
        synchronized (cipher) {
            cipher.init(Cipher.DECRYPT_MODE, getKey());
            return cipher.doFinal(data);
        }
    }
}