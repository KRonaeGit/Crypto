package kronaegit.crypto.cipher.symmetric;

import kronaegit.crypto.CryptoTool;
import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES_GCM extends SymmetricEncryption<SecretKeySpec> {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static final int DEFAULT_IV_LENGTH = 12;      // 96 bits
    private static final int DEFAULT_TAG_LENGTH = 128;    // bits

    private final int iv_bytes;
    private final int tag_bits;
    private final Cipher cipher;
    private final SecureRandom random;

    public AES_GCM(byte[] key, SecureRandom random, int iv_bytes, int tag_bits) throws GeneralSecurityException {
        super(key);
        this.iv_bytes = iv_bytes;
        this.tag_bits = tag_bits;
        this.random = random;
        this.cipher = Cipher.getInstance(TRANSFORMATION);
    }

    public AES_GCM(byte[] key) throws GeneralSecurityException {
        this(key, CryptoTool.random(), DEFAULT_IV_LENGTH, DEFAULT_TAG_LENGTH);
    }

    @Override
    protected SecretKeySpec toKeyObject(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        byte[] iv = new byte[iv_bytes];
        random.nextBytes(iv);

        GCMParameterSpec spec = new GCMParameterSpec(tag_bits, iv);

        synchronized (cipher) {
            cipher.init(Cipher.ENCRYPT_MODE, getKey(), spec);
            byte[] encrypted = cipher.doFinal(data);

            byte[] result = new byte[iv_bytes + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv_bytes);
            System.arraycopy(encrypted, 0, result, iv_bytes, encrypted.length);
            return result;
        }
    }

    @Override
    public byte[] decrypt(byte @NotNull [] encrypted) throws GeneralSecurityException {
        if (encrypted.length < iv_bytes) {
            throw new GeneralSecurityException("Invalid encrypted data (too short)");
        }

        byte[] iv = Arrays.copyOfRange(encrypted, 0, iv_bytes);
        byte[] cipherText = Arrays.copyOfRange(encrypted, iv_bytes, encrypted.length);

        GCMParameterSpec spec = new GCMParameterSpec(tag_bits, iv);

        synchronized (cipher) {
            cipher.init(Cipher.DECRYPT_MODE, getKey(), spec);
            return cipher.doFinal(cipherText);
        }
    }
}
