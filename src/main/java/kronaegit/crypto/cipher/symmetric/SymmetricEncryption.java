package kronaegit.crypto.cipher.symmetric;

import kronaegit.crypto.cipher.Cipher;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public abstract class SymmetricEncryption<K> implements Cipher {
    private final byte[] keyBytes;
    private K key = null;
    public SymmetricEncryption(byte[] key) throws GeneralSecurityException {
        this.keyBytes = key;
    }
    public SymmetricEncryption(String key, Charset charset) throws GeneralSecurityException {
        this(key.getBytes(charset));
    }
    public SymmetricEncryption(String key) throws GeneralSecurityException {
        this(key, StandardCharsets.UTF_8);
    }

    protected abstract K toKeyObject(byte[] key) throws GeneralSecurityException;

    public K getKey() throws GeneralSecurityException {
        synchronized (this) {
            if(key == null)
                this.key = toKeyObject(keyBytes);
            return key;
        }
    }

    public abstract byte[] encrypt(byte[] data) throws GeneralSecurityException;
    public abstract byte[] decrypt(byte[] encrypted) throws GeneralSecurityException;
    public String decryptToString(byte[] encrypted, Charset resultCharset) throws GeneralSecurityException {
        return new String(decrypt(encrypted), resultCharset);
    }
    public String decryptToString(byte[] encrypted) throws GeneralSecurityException {
        return decryptToString(encrypted, StandardCharsets.UTF_8);
    }
}
